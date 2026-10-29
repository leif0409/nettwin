"""Cisco IOS router driver (subset: interfaces, VRF membership, static routes)."""
from __future__ import annotations

from ipaddress import IPv4Address, IPv4Interface, IPv4Network

from twin.drivers.base import Driver
from twin.model import Device, Interface, Route

STATIC_AD = 1


def _is_ip(tok: str) -> bool:
    try:
        IPv4Address(tok)
        return True
    except ValueError:
        return False


class CiscoIOSDriver(Driver):
    vendor = "cisco_ios"
    role = "router"

    def parse(self, text: str) -> Device:
        hostname = "unknown"
        interfaces: list[dict] = []
        routes: list[Route] = []
        unsupported: list[str] = []
        current: dict | None = None

        for raw in text.splitlines():
            if not raw.strip() or raw.strip().startswith("!"):
                current = None if raw.strip() == "!" else current
                continue
            indented = raw[0].isspace()
            tok = raw.split()

            if indented:
                if current is None:
                    continue  # body of a block we don't model (already flagged)
                if tok[:2] == ["ip", "address"] and len(tok) >= 3 and tok[2][0].isdigit():
                    if "secondary" in tok:
                        unsupported.append(f"{current['name']}: secondary address {tok[2]}")
                    elif "/" in tok[2]:  # 10.0.0.1/24 style (IOS-XE alternates, NX-OS, EOS)
                        current["ip"] = IPv4Interface(tok[2])
                    elif len(tok) >= 4:
                        current["ip"] = IPv4Interface(f"{tok[2]}/{tok[3]}")
                elif tok[0] == "shutdown":
                    current["enabled"] = False
                elif tok[0] == "description":
                    current["description"] = " ".join(tok[1:])
                elif tok[:2] == ["vrf", "forwarding"] or tok[:3] == ["ip", "vrf", "forwarding"]:
                    current["vrf"] = tok[-1]
                continue

            current = None
            if tok[0] == "hostname":
                hostname = tok[1]
            elif tok[0] == "interface":
                current = {"name": tok[1]}
                interfaces.append(current)
            elif tok[:2] == ["ip", "route"]:
                routes.append(self._route(tok[2:]))
            elif tok[0] == "router" or tok[:2] == ["ip", "nat"] or tok[:2] == ["ip", "access-list"]:
                unsupported.append(" ".join(tok))

        return Device(
            name=hostname,
            vendor=self.vendor,
            role="router",
            interfaces=[Interface(**i) for i in interfaces],
            routes=routes,
            unsupported=unsupported,
        )

    @staticmethod
    def _route(args: list[str]) -> Route:
        vrf = "default"
        if args[0] == "vrf":
            vrf, args = args[1], args[2:]
        if "/" in args[0]:
            prefix, rest = IPv4Network(args[0]), args[1:]
        else:
            prefix, rest = IPv4Network(f"{args[0]}/{args[1]}"), args[2:]
        next_hop = interface = None
        if _is_ip(rest[0]):
            next_hop, rest = rest[0], rest[1:]
        else:
            interface, rest = rest[0], rest[1:]
            if rest and _is_ip(rest[0]):
                next_hop, rest = rest[0], rest[1:]
        ad = int(rest[0]) if rest and rest[0].isdigit() else STATIC_AD
        return Route(prefix=prefix, next_hop=next_hop, interface=interface, admin_distance=ad, vrf=vrf)
