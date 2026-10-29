"""Fortinet FortiOS firewall driver (subset: interfaces, zones, static routes, objects, policies)."""
from __future__ import annotations

from ipaddress import IPv4Interface, IPv4Network

from twin.drivers.base import Driver, RuleRequest, parse_ports, range_to_prefixes, tokens
from twin.model import ANY, AddressObject, Device, Interface, Policy, PortRange, Route, Service, ServiceEntry

STATIC_AD = 10

BUILTIN_SERVICES = {
    "ALL": [ServiceEntry(protocol="any")],
    "ALL_TCP": [ServiceEntry(protocol="tcp")],
    "ALL_UDP": [ServiceEntry(protocol="udp")],
    "ALL_ICMP": [ServiceEntry(protocol="icmp")],
    "PING": [ServiceEntry(protocol="icmp")],
    "HTTP": [ServiceEntry(protocol="tcp", ports=[PortRange(start=80, end=80)])],
    "HTTPS": [ServiceEntry(protocol="tcp", ports=[PortRange(start=443, end=443)])],
    "SSH": [ServiceEntry(protocol="tcp", ports=[PortRange(start=22, end=22)])],
}


def parse_tree(text: str) -> dict:
    """FortiOS config/edit/set/next/end -> nested dicts. Edit order is preserved (it is policy order)."""
    root: dict = {}
    stack = [root]
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        t = tokens(line)
        if t[0] == "config":
            stack.append(stack[-1].setdefault(" ".join(t[1:]), {}))
        elif t[0] == "edit":
            stack.append(stack[-1].setdefault(t[1], {}))
        elif t[0] == "set":
            stack[-1][t[1]] = t[2:]
        elif t[0] in ("next", "end"):
            stack.pop()
    return root


def _mask_or_cidr(vals: list[str]) -> str:
    return vals[0] if len(vals) == 1 else f"{vals[0]}/{vals[1]}"


class FortiOSDriver(Driver):
    vendor = "fortios"
    role = "firewall"

    def parse(self, text: str) -> Device:
        tree = parse_tree(text)
        unsupported: list[str] = []
        hostname = tree.get("system global", {}).get("hostname", ["unknown"])[0]

        # FortiOS policies match on interface or zone; an interface's "zone" is its zone if it has one, else itself.
        zone_of: dict[str, str] = {}
        for zname, z in tree.get("system zone", {}).items():
            for ifname in z.get("interface", []):
                zone_of[ifname] = zname

        interfaces = []
        for name, i in tree.get("system interface", {}).items():
            ip = i.get("ip")
            ip = IPv4Interface(_mask_or_cidr(ip)) if ip and ip[0] != "0.0.0.0" else None
            interfaces.append(Interface(
                name=name, ip=ip, zone=zone_of.get(name, name),
                enabled=i.get("status", ["up"])[0] != "down",
                description=" ".join(i.get("alias", [])),
                vrf="management" if i.get("dedicated-to", [""])[0] == "management" else "default",
            ))

        routes = []
        for rid, r in tree.get("router static", {}).items():
            if r.get("status", ["enable"])[0] == "disable":
                continue
            if r.get("blackhole", ["disable"])[0] == "enable":
                unsupported.append(f"static route {rid}: blackhole")
                continue
            routes.append(Route(
                prefix=_mask_or_cidr(r.get("dst", ["0.0.0.0", "0.0.0.0"])),
                next_hop=r.get("gateway", [None])[0],
                interface=r.get("device", [None])[0],
                admin_distance=int(r.get("distance", [STATIC_AD])[0]),
            ))

        raw_addrs: dict[str, list[IPv4Network]] = {"all": [IPv4Network("0.0.0.0/0")]}
        for name, a in tree.get("firewall address", {}).items():
            kind = a.get("type", ["ipmask"])[0]
            if kind == "ipmask":
                raw_addrs[name] = [IPv4Network(_mask_or_cidr(a.get("subnet", ["0.0.0.0", "0.0.0.0"])))]
            elif kind == "iprange":
                raw_addrs[name] = range_to_prefixes(a["start-ip"][0], a["end-ip"][0])
            else:
                raw_addrs[name] = []
                unsupported.append(f"address {name} type {kind} (matches nothing in the model)")
        groups = {n: g.get("member", []) for n, g in tree.get("firewall addrgrp", {}).items()}

        raw_svcs = dict(BUILTIN_SERVICES)
        for name, s in tree.get("firewall service custom", {}).items():
            entries = []
            for proto in ("tcp", "udp"):
                if f"{proto}-portrange" in s:
                    ranges = parse_ports(" ".join(s[f"{proto}-portrange"]))
                    entries.append(ServiceEntry(protocol=proto, ports=[PortRange(start=a, end=b) for a, b in ranges]))
            proto = s.get("protocol", [""])[0]
            if proto == "ICMP":
                entries.append(ServiceEntry(protocol="icmp"))
            elif proto == "IP" and s.get("protocol-number", ["0"])[0] == "0":
                entries.append(ServiceEntry(protocol="any"))  # how full configs define the predefined ALL
            raw_svcs[name] = entries
        svc_groups = {n: g.get("member", []) for n, g in tree.get("firewall service group", {}).items()}

        def resolve(name, leaves, grps, seen=frozenset()):
            if name in seen:
                raise ValueError(f"group {name} contains itself")
            if name in leaves:
                return list(leaves[name])
            if name not in grps:
                raise ValueError(f"unknown object {name!r}")
            return [x for m in grps[name] for x in resolve(m, leaves, grps, seen | {name})]

        addresses = {n: AddressObject(name=n, prefixes=resolve(n, raw_addrs, groups)) for n in {*raw_addrs, *groups}}
        services = {n: Service(name=n, entries=resolve(n, raw_svcs, svc_groups)) for n in {*raw_svcs, *svc_groups}}

        def zones(vals: list[str]) -> list[str]:
            return [ANY] if "any" in vals else vals

        def addrs(vals: list[str]) -> list[str]:
            return [ANY] if vals in ([], ["all"]) else vals

        policies = []
        for pid, p in tree.get("firewall policy", {}).items():
            name = p.get("name", [f"policy-{pid}"])[0]
            if p.get("nat", ["disable"])[0] == "enable":
                unsupported.append(f"policy {name}: source NAT not modeled")
            policies.append(Policy(
                name=name,
                src_zones=zones(p.get("srcintf", [])),
                dst_zones=zones(p.get("dstintf", [])),
                src_addrs=addrs(p.get("srcaddr", [])),
                dst_addrs=addrs(p.get("dstaddr", [])),
                services=[ANY] if p.get("service", ["ALL"]) == ["ALL"] else p["service"],
                action="allow" if p.get("action", ["deny"])[0] == "accept" else "deny",
                enabled=p.get("status", ["enable"])[0] != "disable",
                description=" ".join(p.get("comments", [])),
            ))

        return Device(
            name=hostname, vendor=self.vendor, role="firewall",
            interfaces=interfaces, routes=routes, addresses=addresses, services=services,
            policies=policies, default_action="deny", unsupported=unsupported,
        )

    def render_policy(self, rule: RuleRequest) -> str:
        def addr(name: str, net: IPv4Network) -> str:
            return f'    edit "{name}"\n        set subnet {net.network_address} {net.netmask}\n    next'

        parts = ["config firewall address", addr(rule.src_obj, rule.src), addr(rule.dst_obj, rule.dst), "end"]
        if rule.protocol == "icmp":
            svc = "ALL_ICMP"
        else:
            svc = rule.svc_obj
            parts += [
                "config firewall service custom",
                f'    edit "{svc}"\n        set {rule.protocol}-portrange {rule.port}\n    next',
                "end",
            ]
        parts += [
            "config firewall policy",
            "    edit 0",
            f'        set name "{rule.name}"',
            f'        set srcintf "{rule.src_zone}"',
            f'        set dstintf "{rule.dst_zone}"',
            f'        set srcaddr "{rule.src_obj}"',
            f'        set dstaddr "{rule.dst_obj}"',
            f'        set service "{svc}"',
            "        set action accept",
            '        set schedule "always"',
            "        set logtraffic all",
            f'        set comments "{rule.description}"',
            "    next",
            "end",
        ]
        return "\n".join(parts)
