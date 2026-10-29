"""Generate the synthetic "global-corp" lab: 35 devices across NA and EMEA in real vendor syntax.

    python tools/gen_global_lab.py samples/global-corp

SYNTHETIC: the configs follow real Cisco IOS-XE / NX-OS / Junos / PAN-OS / FortiOS syntax,
and each router/switch also gets a routing table in that platform's real output format
(IOS-XE `show ip route`, NX-OS `show ip route vrf all`, Junos `show route | display json`).
Those routing tables are computed here from the design (shortest paths, ECMP), and the
firewalls' static routes are derived from the same paths, so the lab is self-consistent.
NetTwin agreeing with it shows the parsers and analysis work at scale; it is not
independent ground truth (the real-* snapshots are).

Output is deterministic: running it twice gives byte-identical files.

Planted problems (each has a flow in flows.json):
- na-hq-core2 has a "temporary" static for the EMEA app subnet over a legacy backup circuit
  that bypasses na-hq-fw1. core2 is HSRP-active for the HQ users VLAN, so users' requests
  skip the HQ firewall while replies come back through it.
- eu-br-mad-rtr1's BGP export policy has a typo (10.35.20.0/24 instead of 10.35.2.0/24),
  so the Madrid LAN is never advertised: requests leave, replies follow the default to the internet.
- eu-dc1-fw1 explicitly denies NA -> EMEA customer DB (data residency), and has no rule for
  NA IT on tcp/8443 to the EMEA app tier.
- na-dc1-fw1 has a disabled "temp-vendor-access" rule; both internet firewalls have NAT
  (not modeled, flagged).
"""
from __future__ import annotations

import heapq
import json
import sys
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from ipaddress import IPv4Interface, IPv4Network, collapse_addresses, ip_interface, ip_network
from pathlib import Path

DCI_COST = 100
UNADVERTISED = {ip_network("10.35.2.0/24")}  # eu-br-mad LAN (export-policy typo)


# =============================================================================================
# Topology model
# =============================================================================================

@dataclass
class Iface:
    dev: str
    name: str
    ip: IPv4Interface | None
    desc: str = ""
    zone: str = ""
    cost: int = 1
    routed: bool = True      # takes part in routing (False: static-only legacy circuit)
    mgmt: bool = False       # out-of-band management
    vip: str | None = None   # HSRP virtual IP
    prio: int = 100
    vlan: int | None = None
    kind: str = "l3"         # l3 | svi | loop | subif


@dataclass
class Dev:
    name: str
    vendor: str              # iosxe | nxos | junos | panos | fortios
    role: str                # router | switch | firewall
    region: str
    site: str
    model: str
    pos: tuple[int, int]
    asn: int | None = None
    lo: str | None = None
    routing: bool = True     # runs routing (access switches don't: default gateway only)
    ifaces: list[Iface] = field(default_factory=list)
    statics: list[tuple[IPv4Network, str, str]] = field(default_factory=list)  # (prefix, next hop, egress if)
    rib: dict = field(default_factory=dict)  # prefix -> {"nhs": [(if, nh)], "metric": int, "static": bool}

    def iface(self, name: str) -> Iface:
        return next(i for i in self.ifaces if i.name == name)


D: dict[str, Dev] = {}


def dev(name, vendor, role, region, site, model, pos, asn=None, lo=None, routing=True) -> Dev:
    d = Dev(name, vendor, role, region, site, model, pos, asn, lo, routing)
    D[name] = d
    if lo:
        loname = {"iosxe": "Loopback0", "nxos": "loopback0", "junos": "lo0.0"}[vendor]
        add_if(name, loname, f"{lo}/32", "ROUTER-ID", kind="loop")
    return d


def add_if(dev_name: str, name: str, ip: str | None, desc: str = "", **kw) -> Iface:
    i = Iface(dev_name, name, ip_interface(ip) if ip else None, desc, **kw)
    D[dev_name].ifaces.append(i)
    return i


def p2p(a: str, ai: str, b: str, bi: str, net: str, cost: int = 1, routed: bool = True, za: str = "", zb: str = "",
        da: str | None = None, db: str | None = None):
    n = ip_network(net)
    lo, hi = n.network_address, n.network_address + 1
    add_if(a, ai, f"{lo}/{n.prefixlen}", da or f"to {b} {bi}", cost=cost, routed=routed, zone=za)
    add_if(b, bi, f"{hi}/{n.prefixlen}", db or f"to {a} {ai}", cost=cost, routed=routed, zone=zb)


def seg(net: str, desc: str, members: list[tuple[str, str, int, str]]):
    """A shared segment: members are (device, interface, host number, zone)."""
    n = ip_network(net)
    for d, i, host, zone in members:
        add_if(d, i, f"{n.network_address + host}/{n.prefixlen}", desc, zone=zone)


def mgmt(d: str, name: str, ip: str):
    add_if(d, name, ip, "OOB-MGMT", mgmt=True)


# =============================================================================================
# The design: NA (Ashburn DC, New York HQ, 3 branches) and EMEA (Frankfurt DC, London HQ, 3 branches)
# =============================================================================================

def build():
    # ---------------- NA data center ----------------
    dev("na-dc1-wan1", "iosxe", "router", "NA", "NA-DC1 Ashburn", "C8500-12X4QC", (300, 200), 65010, "10.255.1.1")
    dev("na-dc1-wan2", "iosxe", "router", "NA", "NA-DC1 Ashburn", "C8500-12X4QC", (300, 420), 65010, "10.255.1.2")
    dev("na-dc1-fw1", "panos", "firewall", "NA", "NA-DC1 Ashburn", "PA-5450", (520, 300))
    dev("na-dc1-inetfw1", "fortios", "firewall", "NA", "NA-DC1 Ashburn", "FG-1800F", (520, 80))
    dev("na-dc1-core1", "nxos", "switch", "NA", "NA-DC1 Ashburn", "N9K-C9364C", (720, 200), 65010, "10.255.1.3")
    dev("na-dc1-core2", "nxos", "switch", "NA", "NA-DC1 Ashburn", "N9K-C9364C", (720, 420), 65010, "10.255.1.4")
    for n in range(1, 5):
        dev(f"na-dc1-leaf{n}", "nxos", "switch", "NA", "NA-DC1 Ashburn", "N9K-C93180YC-FX", (920, 40 + 140 * n), 65010, f"10.255.1.{10 + n}")

    p2p("na-dc1-wan1", "TenGigabitEthernet0/1/2", "na-dc1-wan2", "TenGigabitEthernet0/1/2", "172.16.0.0/31")
    seg("172.16.1.0/29", "DC1-TRANSIT", [
        ("na-dc1-wan1", "TenGigabitEthernet0/1/0", 1, ""), ("na-dc1-wan2", "TenGigabitEthernet0/1/0", 2, ""),
        ("na-dc1-fw1", "ethernet1/1", 3, "WAN"), ("na-dc1-inetfw1", "port1", 4, "inside")])
    seg("172.16.1.8/29", "DC1-FW-INSIDE", [
        ("na-dc1-fw1", "ethernet1/2", 1, "DC"), ("na-dc1-core1", "Ethernet1/32", 2, ""), ("na-dc1-core2", "Ethernet1/32", 3, "")])
    p2p("na-dc1-core1", "Ethernet1/31", "na-dc1-core2", "Ethernet1/31", "172.16.2.0/31")
    k = 0
    for c in (1, 2):
        for n in range(1, 5):
            p2p(f"na-dc1-core{c}", f"Ethernet1/{n}", f"na-dc1-leaf{n}", f"Ethernet1/{48 + c}", f"172.16.3.{k}/31")
            k += 2
    for n, (vlan, name) in enumerate([(110, "WEB"), (120, "APP"), (130, "DB"), (140, "INFRA")], start=1):
        add_if(f"na-dc1-leaf{n}", f"Vlan{vlan}", f"10.1.{vlan - 100}.1/24", f"{name}-SERVERS", kind="svi", vlan=vlan)
    add_if("na-dc1-inetfw1", "port2", "203.0.113.2/29", "ISP-A", zone="outside")
    add_if("na-dc1-inetfw1", "port3", "10.1.200.1/24", "DMZ", zone="dmz")
    for i, d in enumerate(["na-dc1-core1", "na-dc1-core2", "na-dc1-leaf1", "na-dc1-leaf2", "na-dc1-leaf3", "na-dc1-leaf4"]):
        mgmt(d, "mgmt0", f"192.168.10.{11 + i}/24")
    mgmt("na-dc1-wan1", "GigabitEthernet0", "192.168.11.11/24")
    mgmt("na-dc1-wan2", "GigabitEthernet0", "192.168.11.12/24")
    mgmt("na-dc1-inetfw1", "mgmt", "192.168.12.11/24")

    # ---------------- NA HQ ----------------
    dev("na-hq-fw1", "fortios", "firewall", "NA", "NA-HQ New York", "FG-600E", (420, 620))
    dev("na-hq-core1", "iosxe", "switch", "NA", "NA-HQ New York", "C9500-48Y4C", (300, 790), None, "10.255.1.21")
    dev("na-hq-core2", "iosxe", "switch", "NA", "NA-HQ New York", "C9500-48Y4C", (560, 790), None, "10.255.1.22")
    for n in range(1, 4):
        dev(f"na-hq-acc{n}", "iosxe", "switch", "NA", "NA-HQ New York", "C9300-48P", (180 + 200 * n - 80, 960), routing=False)
    p2p("na-dc1-wan1", "GigabitEthernet0/0/4", "na-hq-fw1", "port1", "172.16.10.0/31", zb="wan")
    p2p("na-dc1-wan2", "GigabitEthernet0/0/4", "na-hq-fw1", "port2", "172.16.10.2/31", zb="wan")
    seg("10.2.0.0/29", "HQ-FW-INSIDE", [("na-hq-fw1", "port3", 1, "lan"), ("na-hq-core1", "TenGigabitEthernet1/0/1", 2, ""),
                                         ("na-hq-core2", "TenGigabitEthernet1/0/1", 3, "")])
    p2p("na-hq-core1", "TenGigabitEthernet1/0/2", "na-hq-core2", "TenGigabitEthernet1/0/2", "10.2.0.8/31")
    # HSRP: core2 is active for USERS (planted), core1 for everything else
    for vlan, name in [(10, "USERS"), (20, "VOICE"), (30, "WIFI"), (40, "PRINTERS"), (50, "IT"), (99, "MGMT")]:
        net = f"10.2.{vlan}"
        p1, p2 = (100, 110) if vlan == 10 else (110, 100)
        add_if("na-hq-core1", f"Vlan{vlan}", f"{net}.2/24", name, kind="svi", vlan=vlan, vip=f"{net}.1", prio=p1)
        add_if("na-hq-core2", f"Vlan{vlan}", f"{net}.3/24", name, kind="svi", vlan=vlan, vip=f"{net}.1", prio=p2)
    for n in range(1, 4):
        add_if(f"na-hq-acc{n}", "Vlan99", f"10.2.99.{10 + n}/24", "MGMT", kind="svi", vlan=99)
    # Legacy backup circuit HQ core2 <-> wan2: not in routing, only a "temporary" static uses it (planted)
    p2p("na-hq-core2", "GigabitEthernet1/0/48", "na-dc1-wan2", "GigabitEthernet0/0/7", "172.16.99.0/31", routed=False,
        da="LEGACY-BACKUP-TO-DC1 (decom pending)", db="LEGACY-BACKUP-TO-HQ (decom pending)")
    mgmt("na-hq-core1", "GigabitEthernet0/0", "192.168.11.21/24")
    mgmt("na-hq-core2", "GigabitEthernet0/0", "192.168.11.22/24")
    mgmt("na-hq-fw1", "mgmt", "192.168.12.21/24")

    # ---------------- NA branches ----------------
    for n, (code, city, model, wan, lan) in enumerate([
        ("chi", "Chicago", "ISR4451-X/K9", "na-dc1-wan1", 1), ("tor", "Toronto", "ISR4431/K9", "na-dc1-wan2", 2),
        ("mex", "Mexico City", "C8300-1N1S-6T", "na-dc1-wan1", 3)]):
        name = f"na-br-{code}-rtr1"
        dev(name, "iosxe", "router", "NA", f"NA-BR {city}", model, (70, 100 + 180 * n), 65101 + n, f"10.255.1.{31 + n}")
        p2p(wan, f"GigabitEthernet0/0/{n + 1}", name, "GigabitEthernet0/0/0", f"172.16.20.{2 * n}/31",
            da=f"BR-{code.upper()}-MPLS-CKT", db="WAN-TO-NA-DC1")
        add_if(name, "GigabitEthernet0/0/1.10", f"10.3.{lan}.1/24", "USERS", kind="subif", vlan=10)
        add_if(name, "GigabitEthernet0/0/1.20", f"10.3.{100 + lan}.1/24", "VOICE", kind="subif", vlan=20)
        mgmt(name, "GigabitEthernet0", f"192.168.11.{31 + n}/24")

    # ---------------- EMEA data center ----------------
    dev("eu-dc1-wan1", "junos", "router", "EMEA", "EU-DC1 Frankfurt", "MX204", (1700, 200), 65020, "10.255.2.1")
    dev("eu-dc1-wan2", "junos", "router", "EMEA", "EU-DC1 Frankfurt", "MX204", (1700, 420), 65020, "10.255.2.2")
    dev("eu-dc1-fw1", "fortios", "firewall", "EMEA", "EU-DC1 Frankfurt", "FG-3000F", (1480, 300))
    dev("eu-dc1-inetfw1", "panos", "firewall", "EMEA", "EU-DC1 Frankfurt", "PA-3440", (1480, 80))
    dev("eu-dc1-core1", "nxos", "switch", "EMEA", "EU-DC1 Frankfurt", "N9K-C9364C", (1280, 200), 65020, "10.255.2.3")
    dev("eu-dc1-core2", "nxos", "switch", "EMEA", "EU-DC1 Frankfurt", "N9K-C9364C", (1280, 420), 65020, "10.255.2.4")
    for n in (1, 2):
        dev(f"eu-dc1-leaf{n}", "nxos", "switch", "EMEA", "EU-DC1 Frankfurt", "N9K-C93180YC-FX", (1080, 180 + 200 * (n - 1)), 65020, f"10.255.2.{10 + n}")
    p2p("eu-dc1-wan1", "xe-0/1/2.0", "eu-dc1-wan2", "xe-0/1/2.0", "172.17.0.0/31")
    seg("172.17.1.0/29", "EU-DC1-TRANSIT", [
        ("eu-dc1-wan1", "xe-0/1/0.0", 1, ""), ("eu-dc1-wan2", "xe-0/1/0.0", 2, ""),
        ("eu-dc1-fw1", "port1", 3, "wan"), ("eu-dc1-inetfw1", "ethernet1/2", 4, "trust")])
    seg("172.17.1.8/29", "EU-DC1-FW-INSIDE", [
        ("eu-dc1-fw1", "port2", 1, "dc"), ("eu-dc1-core1", "Ethernet1/32", 2, ""), ("eu-dc1-core2", "Ethernet1/32", 3, "")])
    p2p("eu-dc1-core1", "Ethernet1/31", "eu-dc1-core2", "Ethernet1/31", "172.17.2.0/31")
    k = 0
    for c in (1, 2):
        for n in (1, 2):
            p2p(f"eu-dc1-core{c}", f"Ethernet1/{n}", f"eu-dc1-leaf{n}", f"Ethernet1/{48 + c}", f"172.17.3.{k}/31")
            k += 2
    for leaf, vlan, name in [(1, 210, "WEB"), (1, 220, "APP"), (2, 230, "DB"), (2, 240, "INFRA")]:
        add_if(f"eu-dc1-leaf{leaf}", f"Vlan{vlan}", f"10.33.{vlan - 200}.1/24", f"{name}-SERVERS", kind="svi", vlan=vlan)
    add_if("eu-dc1-inetfw1", "ethernet1/1", "198.51.100.2/29", "ISP-B", zone="untrust")
    add_if("eu-dc1-inetfw1", "ethernet1/3", "10.33.200.1/24", "DMZ", zone="dmz")
    for i, d in enumerate(["eu-dc1-core1", "eu-dc1-core2", "eu-dc1-leaf1", "eu-dc1-leaf2"]):
        mgmt(d, "mgmt0", f"192.168.20.{11 + i}/24")
    mgmt("eu-dc1-wan1", "fxp0.0", "192.168.21.11/24")
    mgmt("eu-dc1-wan2", "fxp0.0", "192.168.21.12/24")
    mgmt("eu-dc1-fw1", "mgmt", "192.168.22.11/24")

    # ---------------- EMEA HQ ----------------
    dev("eu-hq-fw1", "panos", "firewall", "EMEA", "EU-HQ London", "PA-1420", (1580, 620))
    dev("eu-hq-core1", "iosxe", "switch", "EMEA", "EU-HQ London", "C9500-24Y4C", (1700, 790), None, "10.255.2.21")
    dev("eu-hq-core2", "iosxe", "switch", "EMEA", "EU-HQ London", "C9500-24Y4C", (1460, 790), None, "10.255.2.22")
    for n in (1, 2):
        dev(f"eu-hq-acc{n}", "iosxe", "switch", "EMEA", "EU-HQ London", "C9300-48P", (1780 - 200 * (n - 1) - 100, 960), routing=False)
    p2p("eu-dc1-wan1", "xe-0/1/4.0", "eu-hq-fw1", "ethernet1/1", "172.17.10.0/31", zb="wan")
    p2p("eu-dc1-wan2", "xe-0/1/4.0", "eu-hq-fw1", "ethernet1/2", "172.17.10.2/31", zb="wan")
    seg("10.34.0.0/29", "HQ-FW-INSIDE", [("eu-hq-fw1", "ethernet1/3", 1, "lan"), ("eu-hq-core1", "TenGigabitEthernet1/0/1", 2, ""),
                                          ("eu-hq-core2", "TenGigabitEthernet1/0/1", 3, "")])
    p2p("eu-hq-core1", "TenGigabitEthernet1/0/2", "eu-hq-core2", "TenGigabitEthernet1/0/2", "10.34.0.8/31")
    for vlan, name in [(10, "USERS"), (20, "VOICE"), (50, "IT"), (99, "MGMT")]:
        net = f"10.34.{vlan}"
        add_if("eu-hq-core1", f"Vlan{vlan}", f"{net}.2/24", name, kind="svi", vlan=vlan, vip=f"{net}.1", prio=110)
        add_if("eu-hq-core2", f"Vlan{vlan}", f"{net}.3/24", name, kind="svi", vlan=vlan, vip=f"{net}.1", prio=100)
    for n in (1, 2):
        add_if(f"eu-hq-acc{n}", "Vlan99", f"10.34.99.{10 + n}/24", "MGMT", kind="svi", vlan=99)
    mgmt("eu-hq-core1", "GigabitEthernet0/0", "192.168.21.21/24")
    mgmt("eu-hq-core2", "GigabitEthernet0/0", "192.168.21.22/24")

    # ---------------- EMEA branches ----------------
    dev("eu-br-par-rtr1", "iosxe", "router", "EMEA", "EU-BR Paris", "ISR4331/K9", (1930, 100), 65201, "10.255.2.31")
    p2p("eu-dc1-wan1", "ge-0/0/1.0", "eu-br-par-rtr1", "GigabitEthernet0/0/0", "172.17.20.0/31", da="BR-PAR-MPLS-CKT", db="WAN-TO-EU-DC1")
    add_if("eu-br-par-rtr1", "GigabitEthernet0/0/1.10", "10.35.1.1/24", "USERS", kind="subif", vlan=10)
    add_if("eu-br-par-rtr1", "GigabitEthernet0/0/1.20", "10.35.101.1/24", "VOICE", kind="subif", vlan=20)
    mgmt("eu-br-par-rtr1", "GigabitEthernet0", "192.168.21.31/24")

    dev("eu-br-mad-rtr1", "junos", "router", "EMEA", "EU-BR Madrid", "SRX340", (1930, 280), 65202, "10.255.2.32")
    p2p("eu-dc1-wan2", "ge-0/0/1.0", "eu-br-mad-rtr1", "ge-0/0/0.0", "172.17.20.2/31", da="BR-MAD-MPLS-CKT", db="WAN-TO-EU-DC1")
    add_if("eu-br-mad-rtr1", "ge-0/0/1.0", "10.35.2.1/24", "USERS")
    mgmt("eu-br-mad-rtr1", "fxp0.0", "192.168.21.32/24")

    dev("eu-br-dub-fw1", "fortios", "firewall", "EMEA", "EU-BR Dublin", "FG-100F", (1930, 460))
    p2p("eu-dc1-wan1", "ge-0/0/2.0", "eu-br-dub-fw1", "wan1", "172.17.20.4/31", da="BR-DUB-INTERNET-VPN", db="WAN-TO-EU-DC1")
    add_if("eu-br-dub-fw1", "internal", "10.35.3.1/24", "USERS")

    # ---------------- Transatlantic DCI ----------------
    p2p("na-dc1-wan1", "HundredGigE0/2/0", "eu-dc1-wan1", "et-0/0/0.0", "172.18.0.0/31", cost=DCI_COST,
        da="DCI-TO-EU-DC1-WAN1 (ATL-FRA-01)", db="DCI-TO-NA-DC1-WAN1 (ATL-FRA-01)")
    p2p("na-dc1-wan2", "HundredGigE0/2/0", "eu-dc1-wan2", "et-0/0/0.0", "172.18.0.2/31", cost=DCI_COST,
        da="DCI-TO-EU-DC1-WAN2 (ATL-FRA-02)", db="DCI-TO-NA-DC1-WAN2 (ATL-FRA-02)")


# Internet exits: the default route is "originated" at each region's internet firewall.
DEFAULT_ORIGINS = {"na-dc1-inetfw1": ("203.0.113.1", "port2"), "eu-dc1-inetfw1": ("198.51.100.1", "ethernet1/1")}

# Planted: na-hq-core2 static for the EMEA app subnet over the legacy backup circuit (beats OSPF by AD).
PLANTED_STATICS = {("na-hq-core2", ip_network("10.33.20.0/24")): ("GigabitEthernet1/0/48", "172.16.99.1")}


# =============================================================================================
# Routing: shortest paths (ECMP) over the routed links
# =============================================================================================

def compute_routing():
    adj: dict[str, list[tuple[str, str, str, int]]] = defaultdict(list)  # dev -> (nbr, my_if, nbr_ip, cost)
    by_net: dict[IPv4Network, list[Iface]] = defaultdict(list)
    for d in D.values():
        for i in d.ifaces:
            if i.ip is not None and not i.mgmt:
                by_net[i.ip.network].append(i)
    for net, members in by_net.items():
        routed = [i for i in members if i.routed and D[i.dev].routing]
        for a in routed:
            for b in routed:
                if a.dev != b.dev:
                    adj[a.dev].append((b.dev, a.name, str(b.ip.ip), max(a.cost, b.cost)))

    prefixes: dict[IPv4Network, set[str]] = {}
    for net, members in by_net.items():
        origins = {i.dev for i in members if D[i.dev].routing and i.routed}
        if origins and net not in UNADVERTISED:
            prefixes[net] = origins
    prefixes[ip_network("0.0.0.0/0")] = set(DEFAULT_ORIGINS)

    for prefix, origins in prefixes.items():
        dist = {o: 0 for o in origins}
        heap = [(0, o) for o in sorted(origins)]
        while heap:
            dd, u = heapq.heappop(heap)
            if dd > dist.get(u, 1 << 30):
                continue
            for v, _, _, c in adj[u]:
                if dd + c < dist.get(v, 1 << 30):
                    dist[v] = dd + c
                    heapq.heappush(heap, (dd + c, v))
        for name, d in D.items():
            if not d.routing or name in origins or name not in dist:
                continue
            nhs = sorted({(my_if, nbr_ip) for v, my_if, nbr_ip, c in adj[name] if v in dist and dist[v] + c == dist[name]})
            d.rib[prefix] = {"nhs": nhs, "metric": dist[name], "static": False}

    for (name, prefix), (my_if, nh) in PLANTED_STATICS.items():
        D[name].rib[prefix] = {"nhs": [(my_if, nh)], "metric": 0, "static": True}
        D[name].statics.append((prefix, nh, my_if))

    # Firewalls route statically: derive their static routes from the same shortest paths,
    # summarised. Everything that follows the default route's next hops needs no entry.
    for name, d in D.items():
        if d.role != "firewall":
            continue
        default = ip_network("0.0.0.0/0")
        if name in DEFAULT_ORIGINS:
            gw, gw_if = DEFAULT_ORIGINS[name]
            default_nhs = [(gw_if, gw)]
        else:
            default_nhs = d.rib[default]["nhs"]
        for my_if, nh in default_nhs:
            d.statics.append((default, nh, my_if))
        groups: dict[tuple, list[IPv4Network]] = defaultdict(list)
        for prefix, r in d.rib.items():
            if prefix != default and r["nhs"] != default_nhs:
                groups[tuple(r["nhs"])].append(prefix)
        for nhs, nets in sorted(groups.items()):
            for net in collapse_addresses(sorted(nets)):
                for my_if, nh in nhs:
                    d.statics.append((net, nh, my_if))
        d.statics.sort(key=lambda s: (s[0].prefixlen != 0, s[0].network_address, s[0].prefixlen, s[1]))


def label(d: Dev, prefix: IPv4Network) -> str:
    """Which protocol the route would come from, per the design (affects display only)."""
    r = d.rib[prefix]
    if r["static"]:
        return "static"
    if prefix.prefixlen == 0:
        return "bgp" if d.name.startswith(("na-br", "eu-br")) else "ospf-ext"
    if d.name.startswith(("na-br", "eu-br")):
        return "bgp"
    origin_region = next((x.region for x in D.values() for i in x.ifaces if i.ip and i.ip.network == prefix), d.region)
    from_branch = any(x.name.startswith(("na-br", "eu-br")) for x in D.values() for i in x.ifaces if i.ip and i.ip.network == prefix)
    if d.name.endswith(("wan1", "wan2")) and (origin_region != d.region or from_branch):
        return "bgp"
    if origin_region != d.region or from_branch:
        return "ospf-ext"
    return "ospf"


# =============================================================================================
# Shared object/policy definitions for the firewalls
# =============================================================================================

ADDR = {
    "na-dc-web": "10.1.10.0/24", "na-dc-app": "10.1.20.0/24", "na-dc-db": "10.1.30.0/24", "na-dc-infra": "10.1.40.0/24",
    "na-dc-nms": "10.1.40.30/32", "na-dmz-web": "10.1.200.10/32",
    "na-hq-users": "10.2.10.0/24", "na-hq-voice": "10.2.20.0/24", "na-hq-wifi": "10.2.30.0/24",
    "na-hq-printers": "10.2.40.0/24", "na-hq-it": "10.2.50.0/24",
    "na-br-chi": "10.3.1.0/24", "na-br-tor": "10.3.2.0/24", "na-br-mex": "10.3.3.0/24",
    "na-br-voice": "10.3.100.0/22",
    "eu-dc-all": "10.33.0.0/16", "eu-dc-web": "10.33.10.0/24", "eu-dc-app": "10.33.20.0/24", "eu-dc-db": "10.33.30.0/24",
    "eu-dc-infra": "10.33.40.0/24", "eu-dmz-web": "10.33.200.10/32",
    "eu-hq-users": "10.34.10.0/24", "eu-hq-voice": "10.34.20.0/24", "eu-hq-it": "10.34.50.0/24",
    "eu-br-par": "10.35.1.0/24", "eu-br-mad": "10.35.2.0/24", "eu-br-dub": "10.35.3.0/24", "eu-br-voice": "10.35.101.0/24",
    "corp-na": "10.0.0.0/12", "corp-all": "10.0.0.0/8",
}
GROUPS = {
    "na-branches": ["na-br-chi", "na-br-tor", "na-br-mex"],
    "eu-branches": ["eu-br-par", "eu-br-mad", "eu-br-dub"],
    "emea-users": ["eu-hq-users", "eu-br-par", "eu-br-mad", "eu-br-dub"],
    "corp-voice": ["na-hq-voice", "na-br-voice", "eu-hq-voice", "eu-br-voice"],
}
# Forti custom services (as a full config defines them); PAN service objects use the same ports.
SERVICES = {
    "HTTP": [("tcp", "80")], "HTTPS": [("tcp", "443")], "DNS": [("tcp", "53"), ("udp", "53")], "NTP": [("udp", "123")],
    "SSH": [("tcp", "22")], "RDP": [("tcp", "3389")], "SNMP": [("udp", "161-162")], "SIP": [("udp", "5060")],
    "RTP": [("udp", "16384-32767")], "APP-8443": [("tcp", "8443")], "PRINTER-9100": [("tcp", "9100")],
}

# (name, src zones, dst zones, src, dst, services-or-apps, action, extra)
POLICIES = {
    "na-dc1-fw1": [  # PAN-OS: App-ID where it fits, service objects otherwise
        ("deny-any-to-db", ["WAN"], ["DC"], ["any"], ["na-dc-db"], {"svc": ["any"]}, "deny", {}),
        ("users-to-web", ["WAN"], ["DC"], ["na-hq-users", "na-hq-wifi", "na-branches", "emea-users"], ["na-dc-web"],
         {"apps": ["ssl", "web-browsing"]}, "allow", {}),
        ("users-to-app", ["WAN"], ["DC"], ["na-hq-users", "na-branches"], ["na-dc-app"], {"svc": ["svc-tcp-8443"]}, "allow", {}),
        ("it-to-infra", ["WAN"], ["DC"], ["na-hq-it", "eu-hq-it"], ["na-dc-infra"], {"apps": ["ssh", "ms-rdp", "ldap", "dns"]}, "allow", {}),
        ("temp-vendor-access", ["WAN"], ["DC"], ["any"], ["na-dc-app"], {"svc": ["any"]}, "allow", {"disabled": True}),
        ("dc-to-internet", ["DC"], ["WAN"], ["na-dc-web", "na-dc-app", "na-dc-infra"], ["any"],
         {"apps": ["ssl", "web-browsing", "dns", "ntp"]}, "allow", {}),
        ("dc-to-emea-dc", ["DC"], ["WAN"], ["na-dc-app"], ["eu-dc-all"], {"svc": ["any"]}, "allow", {"desc": "DB replication NA->EU"}),
        ("nms-to-emea", ["DC"], ["WAN"], ["na-dc-nms"], ["eu-dc-infra"], {"apps": ["snmp"]}, "allow", {}),
    ],
    "na-dc1-inetfw1": [  # FortiOS
        ("dmz-to-inside-deny", ["dmz"], ["inside"], ["all"], ["all"], {"svc": ["ALL"]}, "deny", {}),
        ("inside-to-internet", ["inside"], ["outside"], ["corp-all"], ["all"], {"svc": ["HTTP", "HTTPS", "DNS", "NTP"]}, "accept", {"nat": True}),
        ("inside-to-dmz", ["inside"], ["dmz"], ["corp-all"], ["na-dmz-web"], {"svc": ["HTTPS"]}, "accept", {}),
        ("internet-to-dmz", ["outside"], ["dmz"], ["all"], ["na-dmz-web"], {"svc": ["HTTPS"]}, "accept", {"desc": "via VIP"}),
    ],
    "na-hq-fw1": [
        ("users-internet", ["lan"], ["wan"], ["na-hq-users", "na-hq-wifi", "na-hq-it"], ["all"], {"svc": ["HTTP", "HTTPS", "DNS"]}, "accept", {}),
        ("corp-apps", ["lan"], ["wan"], ["na-hq-users", "na-hq-it"], ["corp-all"], {"svc": ["HTTPS", "APP-8443"]}, "accept", {}),
        ("it-admin", ["lan"], ["wan"], ["na-hq-it"], ["corp-all"], {"svc": ["SSH", "RDP", "SNMP"]}, "accept", {}),
        ("voice-out", ["lan"], ["wan"], ["na-hq-voice"], ["corp-voice"], {"svc": ["SIP", "RTP"]}, "accept", {}),
        ("voice-in", ["wan"], ["lan"], ["corp-voice"], ["na-hq-voice"], {"svc": ["SIP", "RTP"]}, "accept", {}),
        ("branch-print", ["wan"], ["lan"], ["na-branches"], ["na-hq-printers"], {"svc": ["PRINTER-9100"]}, "accept", {}),
    ],
    "eu-dc1-fw1": [
        ("gdpr-na-to-db-deny", ["wan"], ["dc"], ["corp-na"], ["eu-dc-db"], {"svc": ["ALL"]}, "deny",
         {"desc": "Data residency: no NA access to EU customer DB"}),
        ("users-to-web", ["wan"], ["dc"], ["eu-hq-users", "eu-branches", "corp-na"], ["eu-dc-web"], {"svc": ["HTTPS"]}, "accept", {}),
        ("eu-users-to-app", ["wan"], ["dc"], ["eu-hq-users", "eu-branches"], ["eu-dc-app"], {"svc": ["HTTPS", "APP-8443"]}, "accept", {}),
        ("na-users-to-app", ["wan"], ["dc"], ["na-hq-users"], ["eu-dc-app"], {"svc": ["HTTPS"]}, "accept", {}),
        ("nms-snmp", ["wan"], ["dc"], ["na-dc-nms"], ["eu-dc-infra"], {"svc": ["SNMP"]}, "accept", {}),
        ("it-to-infra", ["wan"], ["dc"], ["eu-hq-it"], ["eu-dc-infra"], {"svc": ["SSH", "RDP"]}, "accept", {}),
        ("dc-to-wan", ["dc"], ["wan"], ["eu-dc-web", "eu-dc-app", "eu-dc-infra"], ["all"], {"svc": ["HTTP", "HTTPS", "DNS", "NTP"]}, "accept", {}),
    ],
    "eu-dc1-inetfw1": [
        ("dmz-to-trust-deny", ["dmz"], ["trust"], ["any"], ["any"], {"svc": ["any"]}, "deny", {}),
        ("trust-to-internet", ["trust"], ["untrust"], ["corp-all"], ["any"], {"apps": ["ssl", "web-browsing", "dns", "ntp"]}, "allow", {}),
        ("trust-to-dmz", ["trust"], ["dmz"], ["corp-all"], ["eu-dmz-web"], {"apps": ["ssl"]}, "allow", {}),
        ("internet-to-dmz", ["untrust"], ["dmz"], ["any"], ["eu-dmz-web"], {"apps": ["ssl"]}, "allow", {}),
    ],
    "eu-hq-fw1": [
        ("users-web", ["lan"], ["wan"], ["eu-hq-users", "eu-hq-it"], ["any"], {"apps": ["ssl", "web-browsing", "dns"]}, "allow", {}),
        ("it-admin", ["lan"], ["wan"], ["eu-hq-it"], ["corp-all"], {"apps": ["ssh", "ms-rdp", "snmp"]}, "allow", {}),
        ("voice-out", ["lan"], ["wan"], ["eu-hq-voice"], ["corp-voice"], {"svc": ["svc-sip", "svc-rtp"]}, "allow", {}),
        ("voice-in", ["wan"], ["lan"], ["corp-voice"], ["eu-hq-voice"], {"svc": ["svc-sip", "svc-rtp"]}, "allow", {}),
    ],
    "eu-br-dub-fw1": [
        ("lan-to-wan", ["internal"], ["wan1"], ["all"], ["all"], {"svc": ["ALL"]}, "accept", {}),
    ],
}
PAN_SERVICES = {"svc-tcp-8443": ("tcp", "8443"), "svc-sip": ("udp", "5060"), "svc-rtp": ("udp", "16384-32767")}


def uid(*parts: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, "globalcorp.example/" + "/".join(parts)))


def used_objects(rules) -> tuple[list[str], list[str]]:
    names = {n for r in rules for n in r[3] + r[4] if n not in ("any", "all")}
    groups = sorted(n for n in names if n in GROUPS)
    addrs = sorted({m for g in groups for m in GROUPS[g]} | {n for n in names if n in ADDR})
    return addrs, groups


# =============================================================================================
# Config renderers
# =============================================================================================

def mask(net: IPv4Network) -> str:
    return f"{net.network_address} {net.netmask}"


def render_iosxe(d: Dev) -> str:
    switch = d.role == "switch"
    L = [
        "!", "! Last configuration change at 09:14:22 UTC Tue Oct 27 2026 by netadmin",
        "! NVRAM config last updated at 09:14:25 UTC Tue Oct 27 2026 by netadmin", "!",
        "version 17.9", "service timestamps debug datetime msec localtime show-timezone",
        "service timestamps log datetime msec localtime show-timezone", "service password-encryption",
        "service call-home", "no service pad", "platform punt-keepalive disable-kernel-core", "!",
        f"hostname {d.name}", "!", "boot-start-marker", "boot system bootflash:packages.conf", "boot-end-marker", "!",
        "vrf definition Mgmt-intf", " !", " address-family ipv4", " exit-address-family", "!",
        "logging buffered 64000 informational", "no logging console", "enable secret 9 $9$REDACTED$REDACTED", "!",
        "aaa new-model", "!", "aaa group server tacacs+ ISE", " server name ISE-1", " ip vrf forwarding Mgmt-intf", "!",
        "aaa authentication login default group ISE local", "aaa authorization exec default group ISE local",
        "aaa accounting commands 15 default start-stop group ISE", "!", "aaa session-id common",
        f"clock timezone {'EST -5 0' if d.region == 'NA' else 'CET 1 0'}", "!",
        "ip domain name globalcorp.example", "no ip domain lookup", "ip name-server 10.1.40.10 10.33.40.10", "!",
        "login on-success log", "!",
    ]
    if not d.routing:
        L += ["no ip routing", "!"]
    if switch:
        vlans = sorted({i.vlan for x in D.values() if x.site == d.site for i in x.ifaces if i.vlan})
        L += ["vtp mode transparent", "!", "spanning-tree mode rapid-pvst", "spanning-tree extend system-id", "!"]
        names = {i.vlan: i.desc for x in D.values() if x.site == d.site for i in x.ifaces if i.vlan}
        for v in vlans:
            L += [f"vlan {v}", f" name {names[v]}", "!"]
    L += ["username netadmin privilege 15 secret 9 $9$REDACTED$REDACTED", "!", "redundancy", " mode sso", "!"]

    for i in d.ifaces:
        L.append(f"interface {i.name}")
        if i.desc:
            L.append(f" description {i.desc}")
        if i.kind == "subif":
            L.append(f" encapsulation dot1Q {i.vlan}")
        if i.mgmt:
            L += [" vrf forwarding Mgmt-intf", f" ip address {i.ip.ip} {i.ip.netmask}", " negotiation auto"]
        else:
            if switch and i.kind == "l3":
                L.append(" no switchport")
            L.append(f" ip address {i.ip.ip} {i.ip.netmask}")
            if i.vip:
                L += [f" standby version 2", f" standby {i.vlan} ip {i.vip}", f" standby {i.vlan} priority {i.prio}",
                      f" standby {i.vlan} preempt"]
            if i.kind in ("l3",) and i.ip.network.prefixlen >= 30:
                L.append(" ip ospf network point-to-point")
            if i.kind == "l3" and not switch:
                L.append(" negotiation auto")
        L.append("!")
    if switch:
        uplinks = ["TenGigabitEthernet1/1/1", "TenGigabitEthernet1/1/2"] if not d.routing else \
                  [f"TenGigabitEthernet1/0/{n}" for n in (3, 4, 5)]
        for u in uplinks:
            L += [f"interface {u}", " description TRUNK", " switchport trunk allowed vlan 10,20,30,40,50,99",
                  " switchport mode trunk", "!"]
        if not d.routing:
            for p in range(1, 5):
                L += [f"interface GigabitEthernet1/0/{p}", " description USER-PORT", " switchport access vlan 10",
                      " switchport mode access", " switchport voice vlan 20", " spanning-tree portfast", "!"]
    # routing protocol config
    rid = d.lo
    if d.routing and rid:
        ospf_ifs = [i for i in d.ifaces if i.ip and not i.mgmt and i.routed and i.kind != "subif"]
        L += ["router ospf 1", f" router-id {rid}", " passive-interface default"]
        for i in ospf_ifs:
            if i.kind == "l3":
                L.append(f" no passive-interface {i.name}")
        for i in ospf_ifs:
            L.append(f" network {i.ip.network.network_address} {i.ip.hostmask} area 0")
        if d.name.endswith(("wan1", "wan2")):
            L.append(" redistribute bgp {} metric-type 2 subnets route-map BGP-TO-OSPF".format(d.asn))
            L.append(" default-information originate")
        L.append("!")
    if d.asn and d.routing:
        L += [f"router bgp {d.asn}", f" bgp router-id {rid}", " bgp log-neighbor-changes", " no bgp default ipv4-unicast"]
        peers = []
        for i in d.ifaces:
            if not i.ip or i.mgmt or not i.routed or i.ip.network.prefixlen < 30:
                continue
            for x in D.values():
                for j in x.ifaces:
                    if j is not i and j.ip and j.ip.network == i.ip.network and x.asn and x.asn != d.asn:
                        peers.append((str(j.ip.ip), x.asn, x.name))
        for ip, asn, name in peers:
            L += [f" neighbor {ip} remote-as {asn}", f" neighbor {ip} description {name}"]
        L += [" !", " address-family ipv4"]
        for i in d.ifaces:
            if i.kind in ("subif", "loop") and i.ip:
                L.append(f"  network {i.ip.network.network_address} mask {i.ip.netmask}")
        if d.name.endswith(("wan1", "wan2")):
            L.append("  redistribute ospf 1 match internal external 2 route-map OSPF-TO-BGP")
        for ip, _, _ in peers:
            L += [f"  neighbor {ip} activate", f"  neighbor {ip} send-community both", f"  neighbor {ip} soft-reconfiguration inbound"]
        L += ["  maximum-paths 2", " exit-address-family", "!"]
    L += ["ip forward-protocol nd", "no ip http server", "ip http secure-server", "!"]
    gw = "192.168.11.1" if d.region == "NA" else "192.168.21.1"
    if any(i.mgmt for i in d.ifaces):
        L.append(f"ip route vrf Mgmt-intf 0.0.0.0 0.0.0.0 {gw}")
    for prefix, nh, _ in d.statics:
        L.append(f"ip route {mask(prefix)} {nh} name TEMP-DC-MIGRATION-CHG0041877")
    if not d.routing:
        vlan99 = d.iface("Vlan99").ip.network
        L.append(f"ip default-gateway {vlan99.network_address + 1}")
    L += ["ip ssh version 2", "ip scp server enable", "!",
          "ip access-list standard VTY-ACCESS", " 10 permit 10.1.40.0 0.0.0.255", " 20 permit 10.33.40.0 0.0.0.255",
          " 30 permit 192.168.0.0 0.0.255.255", " 40 deny   any log", "!"]
    if d.asn and d.routing:
        L += ["route-map OSPF-TO-BGP permit 10", " match ip address prefix-list CORP-AGGREGATES", "!",
              "route-map BGP-TO-OSPF permit 10", "!",
              "ip prefix-list CORP-AGGREGATES seq 5 permit 10.0.0.0/8 le 32", "!"]
    L += ["logging source-interface GigabitEthernet0 vrf Mgmt-intf" if any(i.mgmt for i in d.ifaces) else "logging source-interface Loopback0",
          "logging host 10.1.40.20", "logging host 10.33.40.20", "!",
          "snmp-server community REDACTED RO VTY-ACCESS", f"snmp-server location {d.site}",
          "snmp-server contact noc@globalcorp.example", "snmp-server enable traps", "!",
          "tacacs server ISE-1", " address ipv4 10.1.40.15", " key 7 REDACTED", "!",
          "banner motd ^C", f"*** {d.name} - GlobalCorp {d.region} - authorized access only ***", "^C", "!",
          "line con 0", " exec-timeout 10 0", " stopbits 1", "line vty 0 15", " access-class VTY-ACCESS in vrf-also",
          " exec-timeout 15 0", " transport input ssh", "!",
          "ntp server 10.1.40.12", "ntp server 10.33.40.12", "!", "end", ""]
    return "\n".join(L)


def render_nxos(d: Dev) -> str:
    vlan_ifs = [i for i in d.ifaces if i.kind == "svi"]
    L = ["!Command: show running-config", "!Running configuration last done at: Tue Oct 27 09:14:22 2026",
         "!Time: Wed Oct 28 10:02:11 2026", "", "version 10.3(4a) Bios:version 05.47", f"hostname {d.name}",
         f"vdc {d.name} id 1", "  limit-resource vlan minimum 16 maximum 4094", "  limit-resource vrf minimum 2 maximum 4096", "",
         "feature tacacs+", "feature scp-server", "feature ospf", "feature bgp", "feature interface-vlan",
         "feature lacp", "feature lldp", "feature bfd", "",
         "username admin password 5 $5$REDACTED  role network-admin", "ip domain-lookup", "ip domain-name globalcorp.example",
         f"tacacs-server host {'10.1.40.15' if d.region == 'NA' else '10.33.40.15'} key 7 \"REDACTED\"",
         "aaa group server tacacs+ ISE", "    server 10.1.40.15", "    use-vrf management", "",
         "snmp-server contact noc@globalcorp.example", f"snmp-server location {d.site}",
         "snmp-server community REDACTED group network-operator",
         "ntp server 10.1.40.12 use-vrf management", "ntp server 10.33.40.12 use-vrf management", ""]
    if vlan_ifs:
        L.append("vlan 1," + ",".join(str(i.vlan) for i in vlan_ifs))
        for i in vlan_ifs:
            L += [f"vlan {i.vlan}", f"  name {i.desc}"]
        L.append("")
    gw = "192.168.10.1" if d.region == "NA" else "192.168.20.1"
    L += ["spanning-tree port type edge bpduguard default", "vrf context management", f"  ip route 0.0.0.0/0 {gw}", ""]
    for i in d.ifaces:
        if i.kind == "svi":
            L += [f"interface {i.name}", f"  description {i.desc}", "  no shutdown", "  no ip redirects",
                  f"  ip address {i.ip}", "  ip router ospf UNDERLAY area 0.0.0.0", "  ip ospf passive-interface", ""]
    for p, i in enumerate(i for i in d.ifaces if i.kind == "svi"):
        for port in (1 + 2 * p, 2 + 2 * p):
            L += [f"interface Ethernet1/{port}", f"  description {i.desc.lower()}-srv-{port:02d}", "  switchport",
                  f"  switchport access vlan {i.vlan}", "  spanning-tree port type edge", "  no shutdown", ""] \
                if not d.name.split("-")[-1].startswith("core") else []
    for i in d.ifaces:
        if i.kind == "l3" and not i.mgmt:
            L += [f"interface {i.name}", f"  description {i.desc}", "  no switchport", "  mtu 9216",
                  f"  ip address {i.ip}"]
            if i.ip.network.prefixlen == 31:
                L.append("  ip ospf network point-to-point")
            L += ["  ip router ospf UNDERLAY area 0.0.0.0", "  no shutdown", ""]
    for i in d.ifaces:
        if i.mgmt:
            L += ["interface mgmt0", "  vrf member management", f"  ip address {i.ip}", ""]
    lo = next(i for i in d.ifaces if i.kind == "loop")
    L += ["interface loopback0", "  description ROUTER-ID", f"  ip address {lo.ip}", "  ip router ospf UNDERLAY area 0.0.0.0", "",
          "line console", "  exec-timeout 10", "line vty", "  exec-timeout 15", "  access-class VTY-ACCESS in",
          "router ospf UNDERLAY", f"  router-id {d.lo}", "  log-adjacency-changes detail", "  passive-interface default", ""]
    return "\n".join(L)


def render_junos(d: Dev) -> str:
    tz = "Europe/Madrid" if "mad" in d.name else "Europe/Berlin"
    L = ["## Last commit: 2026-10-27 09:14:22 CET by netadmin", "set version 22.4R3-S2.11",
         f"set system host-name {d.name}", "set system domain-name globalcorp.example", f"set system time-zone {tz}",
         'set system root-authentication encrypted-password "$6$REDACTED"',
         'set system login user netadmin class super-user authentication encrypted-password "$6$REDACTED"',
         "set system services ssh root-login deny", "set system services netconf ssh",
         "set system syslog host 10.33.40.20 any notice", "set system ntp server 10.33.40.12",
         "set system name-server 10.33.40.10", "set system management-instance"]
    if d.model.startswith("SRX"):
        L += ["set security forwarding-options family mpls mode packet-based"]
    for i in d.ifaces:
        phys, unit = i.name.split(".")
        if i.desc:
            L.append(f'set interfaces {phys} description "{i.desc}"')
        L.append(f"set interfaces {phys} unit {unit} family inet address {i.ip}")
    L += [f"set routing-options router-id {d.lo}", f"set routing-options autonomous-system {d.asn}",
          "set routing-options forwarding-table export ECMP",
          "set routing-instances mgmt_junos routing-options static route 0.0.0.0/0 next-hop 192.168.21.1",
          "set policy-options policy-statement ECMP then load-balance per-packet",
          "set policy-options prefix-list CORP 10.0.0.0/8"]
    lo = next(i for i in d.ifaces if i.kind == "loop")
    if "mad" in d.name:
        # planted typo: LAN is 10.35.2.0/24
        L += ["set policy-options policy-statement EXPORT-LAN term LAN from route-filter 10.35.20.0/24 exact",
              "set policy-options policy-statement EXPORT-LAN term LAN then accept",
              f"set policy-options policy-statement EXPORT-LAN term LO from route-filter {lo.ip.network} exact",
              "set policy-options policy-statement EXPORT-LAN term LO then accept",
              "set policy-options policy-statement EXPORT-LAN then reject"]
    peers = []
    for i in d.ifaces:
        if i.ip and not i.mgmt and i.routed and i.ip.network.prefixlen >= 30:
            for x in D.values():
                for j in x.ifaces:
                    if j is not i and j.ip and j.ip.network == i.ip.network and x.asn and x.asn != d.asn:
                        peers.append((str(j.ip.ip), x.asn, x.name))
    for ip, asn, name in peers:
        grp = "DCI-NA" if name.startswith("na-") else ("BRANCHES" if "br-" in name else "EU-DC1")
        L += [f"set protocols bgp group {grp} type external", f"set protocols bgp group {grp} neighbor {ip} peer-as {asn}",
              f'set protocols bgp group {grp} neighbor {ip} description "{name}"']
        if "mad" in d.name:
            L.append(f"set protocols bgp group {grp} export EXPORT-LAN")
    if "mad" not in d.name:
        for i in d.ifaces:
            if i.ip and not i.mgmt and i.routed and i.kind == "l3" and i.ip.network.prefixlen >= 30:
                L.append(f"set protocols ospf area 0.0.0.0 interface {i.name} interface-type p2p")
        L.append("set protocols ospf area 0.0.0.0 interface lo0.0 passive")
    L += ["set firewall family inet filter PROTECT-RE term SSH from source-prefix-list MGMT-NETS",
          "set firewall family inet filter PROTECT-RE term SSH from protocol tcp",
          "set firewall family inet filter PROTECT-RE term SSH from destination-port ssh",
          "set firewall family inet filter PROTECT-RE term SSH then accept",
          "set snmp community REDACTED authorization read-only", f'set snmp location "{d.site}"', ""]
    return "\n".join(L)


def render_panos(d: Dev) -> str:
    rules = POLICIES[d.name]
    mg = "192.168.12" if d.region == "NA" else "192.168.22"
    L = [f"set deviceconfig system hostname {d.name}",
         f"set deviceconfig system ip-address {mg}.{50 + list(D).index(d.name)}",
         "set deviceconfig system netmask 255.255.255.0", f"set deviceconfig system default-gateway {mg}.1",
         "set deviceconfig system dns-setting servers primary 10.1.40.10",
         "set deviceconfig system dns-setting servers secondary 10.33.40.10",
         "set deviceconfig system ntp-servers primary-ntp-server ntp-server-address 10.1.40.12",
         f"set deviceconfig system timezone {'US/Eastern' if d.region == 'NA' else 'Europe/London'}",
         'set deviceconfig system login-banner "Authorized access only"',
         "set network profiles interface-management-profile PING-ONLY ping yes"]
    data_ifs = [i for i in d.ifaces if not i.mgmt]
    for i in data_ifs:
        L += [f"set network interface ethernet {i.name} layer3 ip {i.ip}",
              f'set network interface ethernet {i.name} comment "{i.desc}"',
              f"set network interface ethernet {i.name} layer3 interface-management-profile PING-ONLY"]
    L.append(f"set network virtual-router default interface [ {' '.join(i.name for i in data_ifs)} ]")
    L += ["set network virtual-router default ecmp enable yes", "set network virtual-router default ecmp max-path 2"]
    for n, (prefix, nh, ifname) in enumerate(d.statics, start=1):
        rn = f"S-{'DEFAULT' if prefix.prefixlen == 0 else str(prefix.network_address).replace('.', '-') + '-' + str(prefix.prefixlen)}-{n}"
        base = f"set network virtual-router default routing-table ip static-route {rn}"
        L += [f"{base} destination {prefix}", f"{base} nexthop ip-address {nh}", f"{base} interface {ifname}", f"{base} metric 10"]
    zones = defaultdict(list)
    for i in data_ifs:
        zones[i.zone].append(i.name)
    for z, ifs in zones.items():
        L.append(f"set zone {z} network layer3 [ {' '.join(ifs)} ]" if len(ifs) > 1 else f"set zone {z} network layer3 {ifs[0]}")
    L += [f"set tag {t} color {c}" for t, c in (("NA", "color3"), ("EMEA", "color5"), ("DC", "color1"))]
    addrs, groups = used_objects(rules)
    for a in addrs:
        L += [f"set address {a} ip-netmask {ADDR[a]}", f"set address {a} tag [ {'NA' if a.startswith(('na-', 'corp')) else 'EMEA'} ]"]
    for g in groups:
        L.append(f"set address-group {g} static [ {' '.join(GROUPS[g])} ]")
    for s, (proto, port) in PAN_SERVICES.items():
        if any(s in r[5].get("svc", []) for r in rules):
            L.append(f"set service {s} protocol {proto} port {port}")
    for name, sz, dz, src, dst, what, action, extra in rules:
        b = f"set rulebase security rules {name}"
        fmt = lambda v: f"[ {' '.join(v)} ]" if len(v) > 1 else v[0]  # noqa: E731
        L += [f"{b} from {fmt(sz)}", f"{b} to {fmt(dz)}", f"{b} source {fmt(src)}", f"{b} destination {fmt(dst)}"]
        if "apps" in what:
            L += [f"{b} application {fmt(what['apps'])}", f"{b} service application-default"]
        else:
            L += [f"{b} application any", f"{b} service {fmt(what['svc'])}"]
        L += [f"{b} action {action}", f"{b} log-setting default", f"{b} profile-setting group default"]
        if extra.get("disabled"):
            L.append(f"{b} disabled yes")
        if extra.get("desc"):
            L.append(f'{b} description "{extra["desc"]}"')
    if d.name.endswith("inetfw1"):
        L += ["set rulebase nat rules OUTBOUND-PAT from trust", "set rulebase nat rules OUTBOUND-PAT to untrust",
              "set rulebase nat rules OUTBOUND-PAT source any", "set rulebase nat rules OUTBOUND-PAT destination any",
              "set rulebase nat rules OUTBOUND-PAT source-translation dynamic-ip-and-port interface-address interface ethernet1/1"]
    L += ["set shared log-settings syslog SIEM server SIEM-1 server 10.33.40.20", ""]
    return "\n".join(L)


def render_fortios(d: Dev) -> str:
    rules = POLICIES[d.name]
    L = [f"#config-version={d.model.replace('-', '')[:6]}-7.2.8-FW-build1639-240313:opmode=0:vdom=0:user=netadmin",
         "#conf_file_ver=2961847503125", "#buildno=1639", "#global_vdom=1",
         "config system global", "    set admin-sport 8443", f'    set alias "{d.model}"', f'    set hostname "{d.name}"',
         f"    set timezone {'12' if d.region == 'NA' else '26'}", "    set admintimeout 15", "end",
         "config system interface"]
    for n, i in enumerate(d.ifaces, start=1):
        L += [f'    edit "{i.name}"', '        set vdom "root"', f"        set ip {i.ip.ip} {i.ip.netmask}"]
        if i.mgmt:
            L += ["        set allowaccess ping https ssh snmp", "        set dedicated-to management"]
        else:
            L += ["        set allowaccess ping", "        set type physical", f'        set alias "{i.desc}"',
                  f"        set role {'wan' if i.zone in ('wan', 'outside') or i.name.startswith('wan') else 'lan'}"]
        L += [f"        set snmp-index {n}", "    next"]
    L.append("end")
    zones = defaultdict(list)
    for i in d.ifaces:
        if not i.mgmt and i.zone:
            zones[i.zone].append(i.name)
    if zones:
        L.append("config system zone")
        for z, ifs in zones.items():
            L += [f'    edit "{z}"', "        set intrazone deny", "        set interface " + " ".join(f'"{x}"' for x in ifs), "    next"]
        L.append("end")
    addrs, groups = used_objects(rules)
    L += ["config firewall address", '    edit "all"', f"        set uuid {uid(d.name, 'all')}", "    next"]
    for a in addrs:
        L += [f'    edit "{a}"', f"        set uuid {uid(d.name, a)}", f"        set subnet {mask(ip_network(ADDR[a]))}", "    next"]
    L.append("end")
    if groups:
        L.append("config firewall addrgrp")
        for g in groups:
            L += [f'    edit "{g}"', f"        set uuid {uid(d.name, g)}", "        set member " + " ".join(f'"{m}"' for m in GROUPS[g]), "    next"]
        L.append("end")
    L += ["config firewall service custom", '    edit "ALL"', '        set category "General"', "        set protocol IP", "    next",
          '    edit "PING"', '        set category "Network Services"', "        set protocol ICMP", "        unset icmptype", "    next"]
    for s, defs in SERVICES.items():
        L += [f'    edit "{s}"', '        set category "Web Access"' if s in ("HTTP", "HTTPS") else '        set category "General"']
        for proto, ports in defs:
            L.append(f"        set {proto}-portrange {ports}")
        L.append("    next")
    L.append("end")
    L.append("config firewall policy")
    for n, (name, sz, dz, src, dst, what, action, extra) in enumerate(rules, start=1):
        q = lambda v: " ".join(f'"{x}"' for x in v)  # noqa: E731
        L += [f"    edit {n}", f'        set name "{name}"', f"        set uuid {uid(d.name, 'policy', name)}",
              f"        set srcintf {q(sz)}", f"        set dstintf {q(dz)}"]
        if action == "accept":
            L.append("        set action accept")
        L += [f"        set srcaddr {q(src)}", f"        set dstaddr {q(dst)}", '        set schedule "always"',
              f"        set service {q(what['svc'])}", "        set logtraffic all"]
        if extra.get("nat"):
            L.append("        set nat enable")
        if extra.get("desc"):
            L.append(f'        set comments "{extra["desc"]}"')
        L.append("    next")
    L += ["end", "config router static"]
    for n, (prefix, nh, ifname) in enumerate(d.statics, start=1):
        L += [f"    edit {n}"]
        if prefix.prefixlen:
            L.append(f"        set dst {mask(prefix)}")
        L += [f"        set gateway {nh}", f'        set device "{ifname}"']
        if prefix.prefixlen == 0:
            L.append('        set comment "default"')
        L.append("    next")
    L += ["end", "config log syslogd setting", "    set status enable", '    set server "10.33.40.20"', "end", ""]
    return "\n".join(L)


# =============================================================================================
# Routing-table renderers (real platform output formats)
# =============================================================================================

def _classful(net: IPv4Network) -> IPv4Network:
    first = int(str(net.network_address).split(".")[0])
    plen = 8 if first < 128 else 16 if first < 192 else 24
    return ip_network(f"{net.network_address}/{plen}", strict=False)


def connected(d: Dev):
    for i in d.ifaces:
        if i.ip is not None and not i.mgmt:
            yield i


def render_ios_routes(d: Dev) -> str:
    entries: list[tuple[IPv4Network, list[str]]] = []
    for i in connected(d):
        entries.append((i.ip.network, [f"C        {i.ip.network} is directly connected, {i.name}"]))
        if i.ip.network.prefixlen < 32:
            entries.append((ip_network(f"{i.ip.ip}/32"), [f"L        {i.ip.ip}/32 is directly connected, {i.name}"]))
    for prefix, r in d.rib.items():
        kind = label(d, prefix)
        code, ad, metric = {"static": ("S", 1, 0), "bgp": ("B", 20, 0), "ospf-ext": ("O E2", 110, 20),
                            "ospf": ("O", 110, 1 + r["metric"])}[kind]
        if prefix.prefixlen == 0:
            code = {"S": "S*", "B": "B*", "O E2": "O*E2", "O": "O*"}[code]
        lines = []
        for n, (my_if, nh) in enumerate(r["nhs"]):
            iface = "" if code.startswith("B") else f", {my_if}"
            text = f"[{ad}/{metric}] via {nh}, 3w2d{iface}"
            lines.append(f"{code:<8} {prefix} {text}" if n == 0 else " " * (10 + len(str(prefix))) + text)
        entries.append((prefix, lines))
    head = ["Codes: L - local, C - connected, S - static, R - RIP, M - mobile, B - BGP",
            "       D - EIGRP, EX - EIGRP external, O - OSPF, IA - OSPF inter area",
            "       N1 - OSPF NSSA external type 1, N2 - OSPF NSSA external type 2",
            "       E1 - OSPF external type 1, E2 - OSPF external type 2, m - OMP",
            "       n - NAT, Ni - NAT inside, No - NAT outside, Nd - NAT DIA",
            "       i - IS-IS, su - IS-IS summary, L1 - IS-IS level-1, L2 - IS-IS level-2",
            "       ia - IS-IS inter area, * - candidate default, U - per-user static route",
            "       H - NHRP, G - NHRP registered, g - NHRP registration summary",
            "       o - ODR, P - periodic downloaded static route, l - LISP",
            "       a - application route", "       + - replicated route, % - next hop override, p - overrides from PfR",
            "       & - replicated local route overrides by connected", ""]
    default = [e for e in entries if e[0].prefixlen == 0]
    gw = d.rib[ip_network("0.0.0.0/0")]["nhs"][0][1] if default else None
    head.append(f"Gateway of last resort is {gw} to network 0.0.0.0" if gw else "Gateway of last resort is not set")
    head.append("")
    out = head + [l for e in default for l in e[1]]
    groups: dict[IPv4Network, list] = defaultdict(list)
    for prefix, lines in entries:
        if prefix.prefixlen:
            groups[_classful(prefix)].append((prefix, lines))
    for major in sorted(groups, key=lambda n: n.network_address):
        items = sorted(groups[major], key=lambda e: (e[0].network_address, e[0].prefixlen))
        masks = {p.prefixlen for p, _ in items}
        if len(masks) > 1:
            out.append(f"      {major} is variably subnetted, {len(items)} subnets, {len(masks)} masks")
            out += [l for _, ls in items for l in ls]
        else:
            # One mask in the major network: IOS prints the mask once in the header, not per entry.
            out.append(f"      {major.network_address}/{masks.pop()} is subnetted, {len(items)} subnets")
            for p, ls in items:
                out.append(ls[0].replace(str(p), str(p.network_address), 1))
                out += ls[1:]
    return "\n".join(out) + "\n"


def _nx_if(name: str) -> str:
    return name.replace("Ethernet", "Eth").replace("loopback", "Lo")


def render_nxos_routes(d: Dev) -> str:
    head = ['IP Route Table for VRF "default"', "'*' denotes best ucast next-hop", "'**' denotes best mcast next-hop",
            "'[x/y]' denotes [preference/metric]", "'%<string>' in via output denotes VRF <string>", ""]
    rows: list[tuple[IPv4Network, list[str]]] = []
    for i in connected(d):
        rows.append((i.ip.network, [f"{i.ip.network}, ubest/mbest: 1/0, attached",
                                    f"    *via {i.ip.ip}, {_nx_if(i.name)}, [0/0], 3w2d, direct"]))
        if i.ip.network.prefixlen < 32:
            rows.append((ip_network(f"{i.ip.ip}/32"), [f"{i.ip.ip}/32, ubest/mbest: 1/0, attached",
                                                       f"    *via {i.ip.ip}, {_nx_if(i.name)}, [0/0], 3w2d, local"]))
    for prefix, r in d.rib.items():
        kind = label(d, prefix)
        lines = [f"{prefix}, ubest/mbest: {len(r['nhs'])}/0"]
        for my_if, nh in r["nhs"]:
            if kind == "ospf":
                lines.append(f"    *via {nh}, {_nx_if(my_if)}, [110/{40 * r['metric'] + 1}], 3w2d, ospf-UNDERLAY, intra")
            else:
                lines.append(f"    *via {nh}, {_nx_if(my_if)}, [110/20], 3w2d, ospf-UNDERLAY, type-2")
        rows.append((prefix, lines))
    rows.sort(key=lambda e: (e[0].network_address, e[0].prefixlen))
    out = head + [l for _, ls in rows for l in ls]
    gw = "192.168.10.1" if d.region == "NA" else "192.168.20.1"
    mg = next(i for i in d.ifaces if i.mgmt)
    out += ["", 'IP Route Table for VRF "management"', "'*' denotes best ucast next-hop", "'**' denotes best mcast next-hop",
            "'[x/y]' denotes [preference/metric]", "'%<string>' in via output denotes VRF <string>", "",
            "0.0.0.0/0, ubest/mbest: 1/0", f"    *via {gw}, [1/0], 3w2d, static",
            f"{mg.ip.network}, ubest/mbest: 1/0, attached", f"    *via {mg.ip.ip}, mgmt0, [0/0], 3w2d, direct"]
    return "\n".join(out) + "\n"


def render_junos_routes(d: Dev) -> str:
    def data(v):
        return [{"data": v}]

    rts = []
    for i in connected(d):
        rts.append((i.ip.network, {"active-tag": data("*"), "protocol-name": data("Direct"), "preference": data("0"),
                                   "age": data("3w2d 04:12:33"), "nh": [{"selected-next-hop": [{"data": [None]}], "via": data(i.name)}]}))
        if i.ip.network.prefixlen < 32:
            rts.append((ip_network(f"{i.ip.ip}/32"), {"active-tag": data("*"), "protocol-name": data("Local"), "preference": data("0"),
                                                      "age": data("3w2d 04:12:33"), "nh-type": data("Local"),
                                                      "nh": [{"nh-local-interface": data(i.name)}]}))
    for prefix, r in d.rib.items():
        kind = label(d, prefix)
        proto, pref = {"bgp": ("BGP", "170"), "ospf": ("OSPF", "10"), "ospf-ext": ("OSPF", "150"), "static": ("Static", "5")}[kind]
        entry = {"active-tag": data("*"), "protocol-name": data(proto), "preference": data(pref), "age": data("3w2d 04:12:33"),
                 "metric": data(str(r["metric"])),
                 "nh": [{"selected-next-hop": [{"data": [None]}], "to": data(nh), "via": data(my_if)} for my_if, nh in r["nhs"]]}
        if proto == "BGP":
            entry["as-path"] = data("65010 I" if d.region == "EMEA" else "65020 I")
            entry["local-preference"] = data("100")
        rts.append((prefix, entry))
    rts.sort(key=lambda e: (e[0].network_address, e[0].prefixlen))
    doc = {"route-information": [{"attributes": {"xmlns": "http://xml.juniper.net/junos/22.4R0/junos-routing"},
                                  "route-table": [{"table-name": data("inet.0"),
                                                   "destination-count": data(str(len(rts))),
                                                   "total-route-count": data(str(len(rts))),
                                                   "active-route-count": data(str(len(rts))),
                                                   "rt": [{"attributes": {"junos:style": "brief"},
                                                           "rt-destination": data(str(p)), "rt-entry": [e]} for p, e in rts]}]}]}
    return json.dumps(doc, indent=4) + "\n\n{master:0}\n"


# =============================================================================================
# Flows: the design's intent (what *should* happen), written before looking at any engine output
# =============================================================================================

FLOWS = [
    ("na-hq-users-to-na-web", "10.2.10.50", "10.1.10.20", "tcp", 443, []),
    ("na-chi-to-na-app-8443", "10.3.1.50", "10.1.20.20", "tcp", 8443, []),
    ("na-chi-to-na-db", "10.3.1.50", "10.1.30.20", "tcp", 1433, ["EXPLICIT_DENY"]),
    ("na-app-to-na-db", "10.1.20.20", "10.1.30.20", "tcp", 1433, []),
    ("na-hq-users-to-internet", "10.2.10.50", "8.8.8.8", "tcp", 443, []),
    ("na-dc-web-to-internet", "10.1.10.20", "151.101.1.1", "tcp", 443, []),
    ("na-hq-users-to-eu-web", "10.2.10.50", "10.33.10.20", "tcp", 443, []),
    ("na-hq-users-to-eu-app", "10.2.10.50", "10.33.20.20", "tcp", 443, ["ASYMMETRIC_NO_SESSION"]),
    ("na-hq-it-to-eu-app-8443", "10.2.50.10", "10.33.20.20", "tcp", 8443, ["POLICY_DENY"]),
    ("na-app-to-eu-db-gdpr", "10.1.20.20", "10.33.30.20", "tcp", 5432, ["EXPLICIT_DENY"]),
    ("na-dmz-to-na-db", "10.1.200.10", "10.1.30.20", "tcp", 1433, ["EXPLICIT_DENY"]),
    ("na-hq-it-to-na-infra-rdp", "10.2.50.10", "10.1.40.10", "tcp", 3389, []),
    ("na-chi-to-hq-printer", "10.3.1.50", "10.2.40.20", "tcp", 9100, []),
    ("na-tor-to-eu-web", "10.3.2.50", "10.33.10.20", "tcp", 443, []),
    ("na-nms-to-eu-infra-snmp", "10.1.40.30", "10.33.40.10", "udp", 161, []),
    ("eu-hq-users-to-na-web", "10.34.10.50", "10.1.10.20", "tcp", 443, []),
    ("eu-hq-it-to-na-infra-ssh", "10.34.50.10", "10.1.40.10", "tcp", 22, []),
    ("eu-hq-voice-to-na-hq-voice", "10.34.20.50", "10.2.20.50", "udp", 5060, []),
    ("eu-hq-users-to-na-hq-users-ssh", "10.34.10.50", "10.2.10.50", "tcp", 22, ["POLICY_DENY"]),
    ("eu-app-to-eu-db", "10.33.20.20", "10.33.30.20", "tcp", 5432, []),
    ("eu-mad-to-eu-web", "10.35.2.50", "10.33.10.20", "tcp", 443, ["REVERSE_UNREACHABLE"]),
    ("eu-dub-to-eu-app-8443", "10.35.3.50", "10.33.20.20", "tcp", 8443, []),
    ("eu-par-to-internet", "10.35.1.50", "1.1.1.1", "tcp", 443, []),
]


def main():
    out = Path(sys.argv[1])
    build()
    compute_routing()
    renderers = {"iosxe": render_iosxe, "nxos": render_nxos, "junos": render_junos, "panos": render_panos, "fortios": render_fortios}
    route_renderers = {"iosxe": ("show_ip_route.txt", render_ios_routes),
                       "nxos": ("show_ip_route_vrf_all.txt", render_nxos_routes),
                       "junos": ("show_route___display_json.txt", render_junos_routes)}
    vendor_id = {"iosxe": "cisco_ios", "nxos": "cisco_nxos", "junos": "junos", "panos": "panos", "fortios": "fortios"}
    (out / "configs").mkdir(parents=True, exist_ok=True)
    inventory = {"description": "SYNTHETIC 35-device two-region network (NA + EMEA) in real vendor syntax, generated by tools/gen_global_lab.py",
                 "devices": []}
    for name, d in D.items():
        cfg = f"configs/{name}.txt"
        (out / cfg).write_text(renderers[d.vendor](d), newline="\n")
        entry = {"file": cfg, "vendor": vendor_id[d.vendor], "site": d.site, "pos": list(d.pos)}
        if d.routing and d.role != "firewall":
            fname, render = route_renderers[d.vendor]
            (out / "state" / name).mkdir(parents=True, exist_ok=True)
            (out / "state" / name / fname).write_text(render(d), newline="\n")
            entry["routes"] = [f"state/{name}/{fname}"]
        inventory["devices"].append(entry)
    (out / "inventory.json").write_text(json.dumps(inventory, indent=2) + "\n", newline="\n")
    flows = [{"name": n, "src": s, "dst": t, "protocol": p, "port": port, "expect": e} for n, s, t, p, port, e in FLOWS]
    (out / "flows.json").write_text("[\n" + ",\n".join("  " + json.dumps(f) for f in flows) + "\n]\n", newline="\n")
    (out / "SOURCE.md").write_text(__doc__.replace("\n    python", "\n\n    python"), newline="\n")
    print(f"{len(D)} devices -> {out}")


if __name__ == "__main__":
    main()
