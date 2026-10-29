"""Cisco IOS / IOS-XE driver, also used for NX-OS (subset: interfaces, VRF membership,
HSRP/VRRP gateways, static routes, default gateway on L2 switches)."""
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
        current: dict | None = None  # interface block being read
        vrf_context: str | None = None  # NX-OS "vrf context X" block (holds that VRF's static routes)
        fhrp = False  # inside an NX-OS "hsrp N" / IOS-XE "vrrp N address-family" sub-block
        switch = False

        for raw in text.splitlines():
            if not raw.strip() or raw.strip().startswith("!"):
                if raw.strip() == "!":
                    current, vrf_context = None, None
                continue
            indented = raw[0].isspace()
            tok = raw.split()

            if indented:
                if vrf_context is not None and tok[:2] == ["ip", "route"]:
                    self._add_route(routes, unsupported, ["vrf", vrf_context, *tok[2:]])
                    continue
                if current is None:
                    continue  # body of a block we don't model (already flagged)
                if tok[:2] == ["ip", "address"] and len(tok) >= 3 and tok[2][0].isdigit():
                    if "secondary" in tok:
                        unsupported.append(f"{current['name']}: secondary address {tok[2]}")
                    elif "/" in tok[2]:  # 10.0.0.1/24 style (NX-OS, IOS-XE alternative)
                        current["ip"] = IPv4Interface(tok[2])
                    elif len(tok) >= 4:
                        current["ip"] = IPv4Interface(f"{tok[2]}/{tok[3]}")
                elif tok[0] == "shutdown":
                    current["enabled"] = False
                elif tok[0] == "description":
                    current["description"] = " ".join(tok[1:])
                elif tok[:2] == ["vrf", "forwarding"] or tok[:3] == ["ip", "vrf", "forwarding"] or tok[:2] == ["vrf", "member"]:
                    current["vrf"] = tok[-1]
                elif tok[0] == "switchport":
                    switch = True
                # HSRP / VRRP, IOS style: "standby 10 ip 10.0.0.1", "standby 10 priority 110",
                # "vrrp 12 ip 192.168.1.254", "vrrp 12 priority 110"
                elif tok[0] in ("standby", "vrrp") and len(tok) >= 4 and tok[2] == "ip" and _is_ip(tok[3]):
                    current["vip"] = tok[3]
                elif tok[0] in ("standby", "vrrp") and len(tok) >= 4 and tok[2] == "priority":
                    current["fhrp_priority"] = int(tok[3])
                # NX-OS "hsrp 10" / IOS-XE "vrrp 12 address-family ipv4" open a sub-block
                elif tok[0] in ("hsrp", "vrrp") and len(tok) >= 2 and tok[1].isdigit():
                    fhrp = True
                elif fhrp and tok[0] == "priority" and len(tok) >= 2 and tok[1].isdigit():
                    current["fhrp_priority"] = int(tok[1])
                elif fhrp and tok[0] in ("ip", "address") and len(tok) >= 2 and _is_ip(tok[1]):
                    current["vip"] = tok[1]
                continue

            current, vrf_context, fhrp = None, None, False
            if tok[0] == "hostname":
                hostname = tok[1]
            elif tok[0] == "interface":
                current = {"name": tok[1]}
                interfaces.append(current)
            elif tok[:2] == ["vrf", "context"] and len(tok) >= 3:
                vrf_context = tok[2]
            elif tok[:2] == ["ip", "route"]:
                self._add_route(routes, unsupported, tok[2:])
            elif tok[:2] == ["ip", "default-gateway"] and len(tok) >= 3:
                # L2 switch without routing: everything goes to this gateway
                routes.append(Route(prefix="0.0.0.0/0", next_hop=tok[2], admin_distance=STATIC_AD))
            elif tok[0] in ("vlan", "spanning-tree") or tok[:2] == ["feature", "interface-vlan"]:
                switch = True
            elif tok[0] == "router" or tok[:2] == ["ip", "nat"] or tok[:2] == ["ip", "access-list"]:
                unsupported.append(" ".join(tok))

        return Device(
            name=hostname,
            vendor=self.vendor,
            role="switch" if switch else "router",
            interfaces=[Interface(**i) for i in interfaces],
            routes=routes,
            unsupported=unsupported,
        )

    @classmethod
    def _add_route(cls, routes: list[Route], unsupported: list[str], args: list[str]) -> None:
        r = cls._route(args)
        if r.interface and r.interface.lower().startswith("null"):
            unsupported.append(f"discard route {r.prefix} -> {r.interface}")
        else:
            routes.append(r)

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


class CiscoNXOSDriver(CiscoIOSDriver):
    """NX-OS running-config: same block structure as IOS (interface blocks, `ip address x/len`,
    `vrf member`, `vrf context` static routes, `hsrp` sub-blocks), so the IOS parser covers it."""

    vendor = "cisco_nxos"
