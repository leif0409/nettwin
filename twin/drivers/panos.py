"""Palo Alto PAN-OS firewall driver ("set" subset: L3 interfaces, zones, static routes, objects, security rules)."""
from __future__ import annotations

from ipaddress import IPv4Network

from twin.drivers.base import Driver, RuleRequest, bracket_values, parse_ports, range_to_prefixes, tokens
from twin.model import ANY, AddressObject, Device, Interface, Policy, PortRange, Route, Service, ServiceEntry

STATIC_AD = 10

BUILTIN_SERVICES = {
    "service-http": [ServiceEntry(protocol="tcp", ports=[PortRange(start=80, end=80), PortRange(start=8080, end=8080)])],
    "service-https": [ServiceEntry(protocol="tcp", ports=[PortRange(start=443, end=443)])],
}


class PanOSDriver(Driver):
    vendor = "panos"
    role = "firewall"

    def parse(self, text: str) -> Device:
        hostname = "unknown"
        if_ips: dict[str, str] = {}
        if_vr: dict[str, str] = {}
        zones: dict[str, str] = {}
        statics: dict[tuple[str, str], dict] = {}
        raw_addrs: dict[str, list[IPv4Network]] = {}
        groups: dict[str, list[str]] = {}
        raw_svcs: dict[str, list[ServiceEntry]] = {}
        svc_groups: dict[str, list[str]] = {}
        rules: dict[str, dict] = {}
        unsupported: list[str] = []

        for line in text.splitlines():
            line = line.strip()
            if not line.startswith("set "):
                continue
            t = tokens(line)[1:]

            if t[:3] == ["deviceconfig", "system", "hostname"]:
                hostname = t[3]
            elif t[:3] == ["network", "interface", "ethernet"]:
                if t[4:6] == ["layer3", "ip"]:
                    if_ips[t[3]] = bracket_values(t[6:])[0]
                elif t[4:6] == ["layer3", "units"]:
                    unsupported.append(f"subinterface {t[3]} {t[6]}")
            elif t[0] == "zone" and t[2:4] == ["network", "layer3"]:
                for ifname in bracket_values(t[4:]):
                    zones[ifname] = t[1]
            elif t[:2] == ["network", "virtual-router"] and t[3:4] == ["interface"]:
                for ifname in bracket_values(t[4:]):
                    if_vr[ifname] = t[2]
            elif t[:2] == ["network", "virtual-router"] and t[3:6] == ["routing-table", "ip", "static-route"]:
                r = statics.setdefault((t[2], t[6]), {"vrf": t[2], "ad": STATIC_AD})
                rest = t[7:]
                if rest[0] == "destination":
                    r["prefix"] = rest[1]
                elif rest[:2] == ["nexthop", "ip-address"]:
                    r["nh"] = rest[2]
                elif rest[0] == "interface":
                    r["iface"] = rest[1]
                elif rest[0] == "admin-dist":
                    r["ad"] = int(rest[1])
                else:
                    unsupported.append(f"static-route {t[6]} {' '.join(rest)}")
            elif t[0] == "address":
                name, kind, val = t[1], t[2], t[3]
                if kind == "ip-netmask":
                    raw_addrs[name] = [IPv4Network(val if "/" in val else f"{val}/32")]
                elif kind == "ip-range":
                    lo, hi = val.split("-")
                    raw_addrs[name] = range_to_prefixes(lo, hi)
                else:
                    raw_addrs[name] = []
                    unsupported.append(f"address {name} type {kind} (matches nothing in the model)")
            elif t[0] == "address-group" and t[2] == "static":
                groups[t[1]] = bracket_values(t[3:])
            elif t[0] == "service" and t[2] == "protocol":
                proto, ports = t[3], t[5]
                raw_svcs[t[1]] = [ServiceEntry(protocol=proto, ports=[PortRange(start=a, end=b) for a, b in parse_ports(ports)])]
            elif t[0] == "service-group":
                svc_groups[t[1]] = bracket_values(t[3:])
            elif t[:3] == ["rulebase", "security", "rules"]:
                rules.setdefault(t[3], {})[t[4]] = bracket_values(t[5:])
            elif t[:2] == ["rulebase", "nat"]:
                key = f"NAT rule {t[3] if len(t) > 3 else ''}".strip()
                if key not in unsupported:
                    unsupported.append(key)

        addresses = {n: AddressObject(name=n, prefixes=self._resolve(n, raw_addrs, groups)) for n in {*raw_addrs, *groups}}
        services = {n: Service(name=n, entries=e) for n, e in BUILTIN_SERVICES.items()}
        services |= {n: Service(name=n, entries=self._resolve(n, raw_svcs, svc_groups)) for n in {*raw_svcs, *svc_groups}}

        policies = []
        for name, r in rules.items():
            apps = r.get("application", [ANY])
            if apps != [ANY]:
                unsupported.append(f"rule {name}: application match {apps} modeled as any application")
            if "source-user" in r and r["source-user"] != [ANY]:
                unsupported.append(f"rule {name}: source-user match modeled as any user")
            svcs = r.get("service", [ANY])
            if "application-default" in svcs:
                unsupported.append(f"rule {name}: application-default modeled as any service")
                svcs = [ANY]
            policies.append(Policy(
                name=name,
                src_zones=r.get("from", [ANY]),
                dst_zones=r.get("to", [ANY]),
                src_addrs=r.get("source", [ANY]),
                dst_addrs=r.get("destination", [ANY]),
                services=svcs,
                action="allow" if r.get("action", ["deny"])[0] == "allow" else "deny",
                enabled=r.get("disabled", ["no"])[0] != "yes",
                description=" ".join(r.get("description", [])),
            ))

        interfaces = [
            Interface(name=n, ip=ip, zone=zones.get(n), vrf=if_vr.get(n, "default"))
            for n, ip in if_ips.items()
        ]
        routes = [
            Route(prefix=r["prefix"], next_hop=r.get("nh"), interface=r.get("iface"), admin_distance=r["ad"], vrf=r["vrf"])
            for r in statics.values()
        ]
        return Device(
            name=hostname, vendor=self.vendor, role="firewall",
            interfaces=interfaces, routes=routes, addresses=addresses, services=services,
            policies=policies, default_action="deny", unsupported=unsupported,
        )

    @staticmethod
    def _resolve(name, leaves: dict, groups: dict, seen=None) -> list:
        seen = seen or set()
        if name in seen:
            raise ValueError(f"group {name} contains itself")
        if name in leaves:
            return list(leaves[name])
        if name not in groups:
            raise ValueError(f"unknown object {name!r}")
        return [x for m in groups[name] for x in PanOSDriver._resolve(m, leaves, groups, seen | {name})]

    def render_policy(self, rule: RuleRequest) -> str:
        lines = [
            f"set address {rule.src_obj} ip-netmask {rule.src}",
            f"set address {rule.dst_obj} ip-netmask {rule.dst}",
        ]
        if rule.protocol == "icmp":
            svc, app = "application-default", "icmp"
        else:
            lines.append(f"set service {rule.svc_obj} protocol {rule.protocol} port {rule.port}")
            svc, app = rule.svc_obj, "any"
        lines.append(
            f"set rulebase security rules {rule.name} from {rule.src_zone} to {rule.dst_zone} "
            f"source {rule.src_obj} destination {rule.dst_obj} service {svc} application {app} "
            f'action allow description "{rule.description}"'
        )
        return "\n".join(lines)
