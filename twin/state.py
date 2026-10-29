"""Parse collected routing tables (device state) into neutral routes.

The routing table is the device's own answer after OSPF, BGP, EIGRP, statics and
redistribution have run, so importing it makes the twin follow dynamic routing
without simulating any protocol. Connected and local routes are skipped: they are
derived from interfaces.

Supported formats:
- Cisco IOS / IOS-XE `show ip route` (also FortiOS `get router info routing-table all`,
  which uses the same layout)
- Cisco NX-OS `show ip route [vrf all]`
- Juniper `show route | display json`
- PAN-OS `show routing route`
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from ipaddress import IPv4Network

from twin.model import Route

IP = r"\d{1,3}(?:\.\d{1,3}){3}"
IOS_PROTOCOL = {"S": "static", "O": "ospf", "B": "bgp", "D": "eigrp", "R": "rip", "i": "isis"}
SKIP_CODES = {"C", "L"}  # connected and local come from interfaces

# Codes: "C", "B*", "O IA", "O E2", and the no-space default forms "O*E2", "O*IA", "D*EX".
IOS_ENTRY = re.compile(rf"^(?P<code>[A-Za-z]{{1,2}}\*?(?:\s?(?:IA|E1|E2|N1|N2|EX|L1|L2|ia|su))?)\s+(?P<ip>{IP})(?:/(?P<len>\d+))?(?P<rest>.*)$")
IOS_CONT = re.compile(r"^\s+\[\d+/\d+\]\s+via\s")
IOS_SUBNETTED = re.compile(rf"^\s+{IP}/(?P<len>\d+) is subnetted")
IOS_VARIABLY = re.compile(rf"^\s+{IP}/\d+ is variably subnetted")
IOS_VRF = re.compile(r"^Routing Table: (?P<vrf>\S+)")
VIA = re.compile(rf"\[(?P<ad>\d+)/(?P<metric>\d+)\]\s+via\s+(?P<nh>{IP})(?P<tail>[^\[]*)")
IFACE = re.compile(r"^[A-Za-z][\w\-/.:]*\d[\w\-/.:]*$")


@dataclass
class ParsedRoutes:
    routes: list[Route] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)


def parse_routes(text: str) -> ParsedRoutes:
    if "VIRTUAL ROUTER" in text or "flags: A:active" in text:
        return parse_panos_routes(text)
    if "ubest/mbest" in text:
        return parse_nxos_routes(text)
    if text.lstrip().startswith("{") and "route-information" in text:
        return parse_junos_json_routes(text)
    return parse_ios_routes(text)


# ---- NX-OS `show ip route [vrf all]` ----------------------------------------

NXOS_VRF = re.compile(r'^IP Route Table for VRF "(?P<vrf>[^"]+)"')
NXOS_PREFIX = re.compile(rf"^(?P<prefix>{IP}/\d+), ubest/mbest:")
NXOS_VIA = re.compile(rf"^\s+\*via (?P<nh>{IP})(?:%[\w-]+)?, (?:(?P<iface>[A-Za-z][\w/.:-]*), )?\[(?P<ad>\d+)/\d+\], [^,]+, (?P<proto>[\w-]+)")
NXOS_SKIP = {"direct", "local", "hsrp", "vrrp", "glbp", "am"}


def parse_nxos_routes(text: str) -> ParsedRoutes:
    out = ParsedRoutes()
    vrf, prefix = "default", None
    for line in text.splitlines():
        if m := NXOS_VRF.match(line):
            vrf, prefix = m["vrf"], None
        elif m := NXOS_PREFIX.match(line):
            prefix = IPv4Network(m["prefix"], strict=False)
        elif prefix is not None and (m := NXOS_VIA.match(line)):
            proto = m["proto"].split("-")[0]
            if proto in NXOS_SKIP:
                continue
            if m["iface"] and m["iface"].lower().startswith("null"):
                out.skipped.append(f"{prefix} ({proto} discard)")
                continue
            out.routes.append(Route(prefix=prefix, next_hop=m["nh"], interface=m["iface"],
                                    protocol=proto if proto in ("static", "ospf", "bgp", "eigrp", "rip", "isis") else "other",
                                    admin_distance=int(m["ad"]), vrf=vrf))
    return out


# ---- Junos `show route | display json` ---------------------------------------

JUNOS_PROTOCOL = {"Static": "static", "OSPF": "ospf", "OSPF3": "ospf", "BGP": "bgp", "RIP": "rip", "IS-IS": "isis"}


def parse_junos_json_routes(text: str) -> ParsedRoutes:
    import json

    def val(node: dict, key: str, default=None):
        items = node.get(key) or []
        return items[0].get("data", default) if items else default

    out = ParsedRoutes()
    # Captured CLI output often carries the prompt after the JSON (e.g. "{master:0}"):
    # decode the first complete JSON document and ignore the rest.
    doc, _ = json.JSONDecoder().raw_decode(text[text.index("{"):])
    for info in doc.get("route-information", []):
        for table in info.get("route-table", []):
            name = val(table, "table-name", "")
            if not name.endswith("inet.0"):
                continue  # IPv4 unicast tables only (inet.0 and <instance>.inet.0)
            vrf = "default" if name == "inet.0" else name.rsplit(".inet.0", 1)[0]
            for rt in table.get("rt", []):
                prefix = IPv4Network(val(rt, "rt-destination"), strict=False)
                for entry in rt.get("rt-entry", []):
                    if val(entry, "active-tag") not in ("*", "+"):
                        continue
                    proto_name = val(entry, "protocol-name", "")
                    if proto_name in ("Direct", "Local", "Access-internal"):
                        continue
                    hops = [nh for nh in entry.get("nh", []) if "selected-next-hop" in nh] or entry.get("nh", [])[:1]
                    if not hops:
                        out.skipped.append(f"{prefix} ({proto_name} discard/reject)")
                    for nh in hops:
                        to, via = val(nh, "to"), val(nh, "via")
                        if to is None and via is None:
                            out.skipped.append(f"{prefix} ({proto_name} {val(nh, 'nh-type', 'no next hop')})")
                            continue
                        out.routes.append(Route(prefix=prefix, next_hop=to, interface=via,
                                                protocol=JUNOS_PROTOCOL.get(proto_name, "other"),
                                                admin_distance=int(val(entry, "preference", 0)), vrf=vrf))
    return out


def _classful(ip: str) -> int:
    first = int(ip.split(".")[0])
    return 8 if first < 128 else 16 if first < 192 else 24


def _interface(tail: str) -> str | None:
    for part in tail.split(","):
        part = part.strip()
        if IFACE.match(part) and not part[0].isdigit():
            return part
    return None


def parse_ios_routes(text: str) -> ParsedRoutes:
    out = ParsedRoutes()
    vrf, mask = "default", None
    last: tuple[str, IPv4Network] | None = None  # (protocol, prefix) for continuation lines

    def add(protocol: str, prefix: IPv4Network, rest: str):
        hops = list(VIA.finditer(rest))
        if not hops:
            iface = _interface(rest.split("connected", 1)[-1]) if "connected" in rest else None
            if iface and not iface.lower().startswith("null"):
                out.routes.append(Route(prefix=prefix, interface=iface, protocol=protocol, admin_distance=1, vrf=vrf))
            else:
                out.skipped.append(f"{prefix} ({protocol}, {rest.strip()[:40] or 'no next hop'})")
            return
        for h in hops:
            iface = _interface(h["tail"])
            if iface and iface.lower().startswith("null"):
                out.skipped.append(f"{prefix} ({protocol} discard)")
                continue
            out.routes.append(Route(prefix=prefix, next_hop=h["nh"], interface=iface, protocol=protocol,
                                    admin_distance=int(h["ad"]), vrf=vrf))

    for line in text.splitlines():
        if m := IOS_VRF.match(line):
            vrf, mask, last = m["vrf"], None, None
            continue
        if m := IOS_SUBNETTED.match(line):
            mask = int(m["len"])
            continue
        if IOS_VARIABLY.match(line):
            mask = None
            continue
        if IOS_CONT.match(line) and last:
            add(last[0], last[1], line)
            continue
        m = IOS_ENTRY.match(line)
        if not m:
            continue
        code = m["code"].split()[0].rstrip("*")
        # Entries under a "x/len is subnetted" header omit the length.
        plen = int(m["len"]) if m["len"] else (mask if mask is not None else _classful(m["ip"]))
        prefix = IPv4Network(f"{m['ip']}/{plen}", strict=False)
        if code in SKIP_CODES:
            last = None
            continue
        protocol = IOS_PROTOCOL.get(code[0], "other")
        last = (protocol, prefix)
        add(protocol, prefix, m["rest"])
    return out


PAN_PROTOCOL = {"S": "static", "O": "ospf", "B": "bgp", "R": "rip"}
PAN_IFACE = re.compile(r"^(ethernet|ae|tunnel|loopback|vlan)[\d./]*")


def parse_panos_routes(text: str) -> ParsedRoutes:
    out = ParsedRoutes()
    vrf = "default"
    for line in text.splitlines():
        if line.startswith("VIRTUAL ROUTER:"):
            vrf = line.split()[2]
            continue
        t = line.split()
        if len(t) < 4 or not re.fullmatch(rf"{IP}/\d+", t[0]):
            continue
        dest, nh, rest = t[0], t[1], t[3:]
        flags = [x for x in rest if re.fullmatch(r"[A-Z?~][a-z0-9]?", x)]
        if "A" not in flags:
            continue  # inactive
        kind = next((f for f in flags if f[0] in "SOBRCH"), "")
        if not kind or kind[0] in "CH":
            continue  # connected / host: derived from interfaces
        iface = next((x for x in rest if PAN_IFACE.match(x)), None)
        if nh in ("discard", "drop"):
            out.skipped.append(f"{dest} (discard)")
            continue
        next_hop = nh if re.fullmatch(IP, nh) and nh != "0.0.0.0" else None
        if next_hop is None and iface is None:
            out.skipped.append(f"{dest} (no next hop)")
            continue
        out.routes.append(Route(prefix=IPv4Network(dest, strict=False), next_hop=next_hop, interface=iface,
                                protocol=PAN_PROTOCOL.get(kind[0], "other"), admin_distance=10, vrf=vrf))
    return out
