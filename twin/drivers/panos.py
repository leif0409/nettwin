"""Palo Alto PAN-OS firewall driver ("set" subset: L3 interfaces, zones, static routes, objects,
security rules, and App-ID applications with their default ports)."""
from __future__ import annotations

from ipaddress import IPv4Network

from twin.drivers.base import Driver, RuleRequest, bracket_values, parse_ports, range_to_prefixes, tokens
from twin.model import ANY, AddressObject, Device, Interface, Policy, PortRange, Route, Service, ServiceEntry

STATIC_AD = 10


def _tcp(*ports: int) -> list[ServiceEntry]:
    return [ServiceEntry(protocol="tcp", ports=[PortRange(start=p, end=p) for p in ports])]


def _udp(*ports: int) -> list[ServiceEntry]:
    return [ServiceEntry(protocol="udp", ports=[PortRange(start=p, end=p) for p in ports])]


# Default ports of common App-ID applications. With `service application-default`, a rule
# listing these applications only matches their standard ports. Apps not listed here (and
# not defined in the config) are modeled as "any service" and flagged.
BUILTIN_APPS: dict[str, list[ServiceEntry]] = {
    "ping": [ServiceEntry(protocol="icmp")], "icmp": [ServiceEntry(protocol="icmp")],
    "traceroute": [ServiceEntry(protocol="icmp")] + _udp(33434),
    "ssh": _tcp(22), "telnet": _tcp(23), "ftp": _tcp(21), "smtp": _tcp(25, 587),
    "dns": _udp(53) + _tcp(53), "ntp": _udp(123), "snmp": _udp(161), "syslog": _udp(514),
    "web-browsing": _tcp(80), "ssl": _tcp(443),
    "ldap": _tcp(389), "kerberos": _tcp(88) + _udp(88), "ms-rdp": _tcp(3389),
    "mysql": _tcp(3306), "postgres": _tcp(5432), "mssql-db": _tcp(1433), "oracle": _tcp(1521),
    "radius": _udp(1812, 1813), "tacacs-plus": _tcp(49),
}

BUILTIN_SERVICES = {
    "service-http": [ServiceEntry(protocol="tcp", ports=[PortRange(start=80, end=80), PortRange(start=8080, end=8080)])],
    "service-https": [ServiceEntry(protocol="tcp", ports=[PortRange(start=443, end=443)])],
}


def _entries(specs: list[str]) -> list[ServiceEntry]:
    """['tcp/9100', 'udp/53,123'] -> service entries."""
    out = []
    for spec in specs:
        proto, _, ports = spec.partition("/")
        if proto in ("tcp", "udp"):
            out.append(ServiceEntry(protocol=proto, ports=[PortRange(start=a, end=b) for a, b in parse_ports(ports)]))
    return out


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
        overrides: dict[str, dict] = {}
        app_ports: dict[str, list[str]] = {}
        unsupported: list[str] = []

        for line in text.splitlines():
            line = line.strip()
            if not line.startswith("set "):
                continue
            t = tokens(line)[1:]
            if len(t) < 3:
                continue  # empty container lines such as "set service"
            try:
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
                elif t[0] == "address" and len(t) >= 4:
                    name, kind, val = t[1], t[2], t[3]
                    if kind == "ip-netmask":
                        raw_addrs[name] = [IPv4Network(val if "/" in val else f"{val}/32", strict=False)]
                    elif kind == "ip-range":
                        lo, hi = val.split("-")
                        raw_addrs[name] = range_to_prefixes(lo, hi)
                    else:
                        raw_addrs[name] = []
                        unsupported.append(f"address {name} type {kind} (matches nothing in the model)")
                elif t[0] == "address-group" and t[2] == "static":
                    groups[t[1]] = bracket_values(t[3:])
                elif t[0] == "service" and t[2] == "protocol":
                    raw_svcs[t[1]] = [ServiceEntry(protocol=t[3], ports=[PortRange(start=a, end=b) for a, b in parse_ports(t[5])])]
                elif t[0] == "service-group":
                    svc_groups[t[1]] = bracket_values(t[3:])
                elif t[:3] == ["rulebase", "security", "rules"] and len(t) >= 5:
                    rules.setdefault(t[3], {})[t[4]] = bracket_values(t[5:])
                elif t[:3] == ["rulebase", "application-override", "rules"] and len(t) >= 5:
                    overrides.setdefault(t[3], {})[t[4]] = bracket_values(t[5:])
                elif t[0] == "application" and t[2:4] == ["default", "port"]:
                    app_ports.setdefault(t[1], []).extend(bracket_values(t[4:]))
                elif t[:2] == ["rulebase", "nat"] and len(t) > 3:
                    key = f"NAT rule {t[3]}"
                    if key not in unsupported:
                        unsupported.append(key)
            except (IndexError, ValueError) as e:
                unsupported.append(f"unparsed line ({type(e).__name__}): {line[:90]}")

        addresses = {n: AddressObject(name=n, prefixes=self._resolve(n, raw_addrs, groups)) for n in {*raw_addrs, *groups}}
        services = {n: Service(name=n, entries=e) for n, e in BUILTIN_SERVICES.items()}
        services |= {n: Service(name=n, entries=self._resolve(n, raw_svcs, svc_groups)) for n in {*raw_svcs, *svc_groups}}

        # Custom applications: ports come from application-override rules and "default port".
        apps: dict[str, list[ServiceEntry]] = {n: _entries(specs) for n, specs in app_ports.items()}
        for o in overrides.values():
            for app in o.get("application", []):
                proto, ports = o.get("protocol", [""])[0], o.get("port", [""])[0]
                apps.setdefault(app, []).extend(_entries([f"{proto}/{ports}"]))

        policies = []
        for name, r in rules.items():
            app_list = r.get("application", [ANY])
            svcs = r.get("service", [ANY])
            if app_list != [ANY] and svcs == ["application-default"]:
                known = {a: apps.get(a) or BUILTIN_APPS.get(a) for a in app_list}
                unknown = [a for a, e in known.items() if not e]
                if unknown:
                    unsupported.append(f"rule {name}: application(s) {unknown} have no known ports; rule modeled as any service")
                    svcs = [ANY]
                else:
                    sname = f"app-default:{name}"
                    services[sname] = Service(name=sname, entries=[e for es in known.values() for e in es])
                    svcs = [sname]
            elif app_list != [ANY]:
                unsupported.append(f"rule {name}: application match {app_list} not modeled; only its service is checked")
            elif "application-default" in svcs:
                unsupported.append(f"rule {name}: application-default with application any modeled as any service")
                svcs = [ANY]
            if "source-user" in r and r["source-user"] != [ANY]:
                unsupported.append(f"rule {name}: source-user match modeled as any user")
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
            for r in statics.values() if "prefix" in r
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
