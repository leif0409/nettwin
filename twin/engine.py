"""Path engine and analysis over the neutral model.

Computes forwarding paths from the devices' own routing data (longest prefix
match, admin distance, ECMP), evaluates firewall policy at every firewall on
the path, and compares the forward path with the return path to catch
asymmetric routing around stateful firewalls.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import IPv4Address

from twin.model import ANY, Device, Flow, Network, Route

MAX_HOPS = 32

# Issue kinds
FORWARD_UNREACHABLE = "FORWARD_UNREACHABLE"
REVERSE_UNREACHABLE = "REVERSE_UNREACHABLE"
POLICY_DENY = "POLICY_DENY"  # no rule matched; default deny. A rule can be added.
EXPLICIT_DENY = "EXPLICIT_DENY"  # a deny rule matched. Needs a human, never auto-fixed.
ASYMMETRIC_BYPASS = "ASYMMETRIC_BYPASS"  # firewall sees the request but the reply skips it
ASYMMETRIC_NO_SESSION = "ASYMMETRIC_NO_SESSION"  # reply crosses a firewall that never saw the request


@dataclass
class Hop:
    device: str
    in_interface: str | None
    out_interface: str | None
    in_zone: str | None = None
    out_zone: str | None = None
    is_firewall: bool = False

    def __str__(self) -> str:
        if self.is_firewall:
            return f"{self.device}[{self.in_zone}->{self.out_zone}]"
        return f"{self.device}[{self.in_interface}->{self.out_interface}]"


@dataclass
class Path:
    hops: list[Hop]
    status: str  # delivered | no_route | loop | leaves_model | no_ingress | too_long
    detail: str = ""

    @property
    def delivered(self) -> bool:
        return self.status == "delivered"

    @property
    def firewalls(self) -> list[str]:
        return [h.device for h in self.hops if h.is_firewall]

    def __str__(self) -> str:
        return " -> ".join(str(h) for h in self.hops) + f"  [{self.status}{': ' + self.detail if self.detail else ''}]"


@dataclass
class Decision:
    action: str
    rule: str | None  # None = default action, no rule matched

    @property
    def explicit(self) -> bool:
        return self.rule is not None


@dataclass
class FirewallCheck:
    device: str
    in_zone: str | None
    out_zone: str | None
    decision: Decision


@dataclass
class Issue:
    kind: str
    device: str | None
    message: str


@dataclass
class FlowReport:
    flow: Flow
    forward: list[Path]
    reverse: list[Path]
    checks: list[FirewallCheck] = field(default_factory=list)
    issues: list[Issue] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.issues

    def kinds(self) -> list[str]:
        return sorted({i.kind for i in self.issues})


class Twin:
    def __init__(self, network: Network):
        self.network = network
        self.warnings: list[str] = []
        self._owner: dict[IPv4Address, tuple[str, str]] = {}
        for dev in network.devices.values():
            for i in dev.interfaces:
                if i.enabled and i.ip is not None:
                    self._owner[i.ip.ip] = (dev.name, i.name)
        # An HSRP/VRRP virtual IP belongs to whichever device is active for it.
        for vip, (dev_name, if_name) in self._active_gateways().items():
            self._owner.setdefault(vip, (dev_name, if_name))
        # id(route) -> [(egress interface, adjacent next-hop IP or None)], after recursive resolution
        self._res: dict[int, list[tuple[str, IPv4Address | None]]] = {}
        self._rib = {name: self._build_rib(dev) for name, dev in network.devices.items()}

    # ---- routing ---------------------------------------------------------

    def _build_rib(self, dev: Device) -> list[Route]:
        """Connected routes plus routes whose next hop resolves, directly or recursively
        (e.g. a BGP next hop on a loopback reached via OSPF), through up interfaces."""
        rib = dev.connected_routes()
        pending = []
        for r in dev.routes:
            if r.interface is not None and not dev.interface(r.interface).enabled:
                self.warnings.append(f"{dev.name}: route {r.prefix} not installed, interface {r.interface} is down")
            elif r.next_hop is None:
                rib.append(r)
                self._res[id(r)] = [(r.interface, None)]
            else:
                pending.append(r)
        for _ in range(5):  # each pass can resolve routes that depend on routes installed in the last one
            unresolved = []
            for r in pending:
                hops = self._resolve(dev, rib, r)
                if hops:
                    rib.append(r)
                    self._res[id(r)] = hops
                else:
                    unresolved.append(r)
            if len(unresolved) == len(pending):
                break
            pending = unresolved
        for r in pending:
            self.warnings.append(f"{dev.name}: route {r.prefix} not installed, next hop {r.next_hop} unreachable")
        return rib

    def _resolve(self, dev: Device, rib: list[Route], r: Route) -> list[tuple[str, IPv4Address | None]]:
        if r.interface is not None:
            return [(r.interface, r.next_hop)]
        direct = self._egress(dev, r.next_hop, r.vrf)
        if direct is not None:
            return [(direct, r.next_hop)]
        # Never resolve a next hop through the default route: that would make a route whose
        # next hop is really gone look healthy (and is off by default on many platforms).
        via = [b for b in self._best([x for x in rib if x.prefix.prefixlen > 0], r.next_hop, r.vrf)
               if b.prefix != r.prefix]
        hops = []
        for b in via:
            for out_if, adj in self._res.get(id(b), []):
                hop = (out_if, adj or r.next_hop)
                if hop not in hops:
                    hops.append(hop)
        return hops

    @staticmethod
    def _egress(dev: Device, next_hop: IPv4Address, vrf: str) -> str | None:
        for i in dev.interfaces:
            if i.enabled and i.ip is not None and i.vrf == vrf and next_hop in i.ip.network:
                return i.name
        return None

    def lookup(self, device: str, dst: IPv4Address, vrf: str = "default") -> list[Route]:
        """Best routes: longest prefix, then lowest admin distance. Several results = ECMP."""
        return self._best(self._rib[device], dst, vrf)

    @staticmethod
    def _best(rib: list[Route], dst: IPv4Address, vrf: str) -> list[Route]:
        cands = [r for r in rib if r.vrf == vrf and dst in r.prefix]
        if not cands:
            return []
        longest = max(r.prefix.prefixlen for r in cands)
        cands = [r for r in cands if r.prefix.prefixlen == longest]
        best = min(r.admin_distance for r in cands)
        return [r for r in cands if r.admin_distance == best]

    def _active_gateways(self) -> dict[IPv4Address, tuple[str, str]]:
        """vip -> (device, interface) of the active HSRP/VRRP member: highest priority, then highest
        interface IP (the tie-break both protocols use)."""
        best: dict[IPv4Address, tuple[tuple[int, IPv4Address], str, str]] = {}
        for dev in self.network.devices.values():
            for i in dev.interfaces:
                if i.enabled and i.ip is not None and i.vip is not None:
                    rank = (i.fhrp_priority, i.ip.ip)
                    if i.vip not in best or rank > best[i.vip][0]:
                        best[i.vip] = (rank, dev.name, i.name)
        return {vip: (d, n) for vip, (_, d, n) in best.items()}

    def ingress_for(self, ip: IPv4Address) -> list[tuple[str, str]]:
        """First-hop devices: those with an up interface whose connected subnet holds `ip` (most
        specific wins). Where the subnet has an HSRP/VRRP gateway, only the active member forwards."""
        hits = [
            (i.ip.network.prefixlen, dev.name, i)
            for dev in self.network.devices.values()
            for i in dev.interfaces
            if i.enabled and i.ip is not None and ip in i.ip.network
        ]
        if not hits:
            return []
        longest = max(h[0] for h in hits)
        hits = [(d, i) for plen, d, i in hits if plen == longest]
        vips = {i.vip for _, i in hits if i.vip is not None}
        if vips:
            active = self._active_gateways()
            gateways = [active[v] for v in sorted(vips)]
            return sorted(set(gateways))
        return sorted((d, i.name) for d, i in hits)

    def trace(self, src: IPv4Address, dst: IPv4Address) -> list[Path]:
        starts = self.ingress_for(src)
        if not starts:
            return [Path([], "no_ingress", f"no device has a connected subnet containing {src}")]
        paths: list[Path] = []
        for dev, iface in starts:
            self._walk(dev, iface, dst, [], frozenset(), paths)
        return paths

    def _hop(self, dev: Device, in_if: str | None, out_if: str | None) -> Hop:
        zone = lambda n: dev.interface(n).zone if n and dev.interface(n) else None  # noqa: E731
        return Hop(dev.name, in_if, out_if, zone(in_if), zone(out_if), dev.role == "firewall")

    def _walk(self, name: str, in_if: str, dst: IPv4Address, hops: list[Hop], seen: frozenset, out: list[Path]):
        dev = self.network.devices[name]
        if name in seen:
            out.append(Path(hops + [self._hop(dev, in_if, None)], "loop", f"{name} reached twice"))
            return
        if len(hops) >= MAX_HOPS:
            out.append(Path(hops, "too_long", f"more than {MAX_HOPS} hops"))
            return
        vrf = dev.interface(in_if).vrf
        routes = self.lookup(name, dst, vrf)
        if not routes:
            out.append(Path(hops + [self._hop(dev, in_if, None)], "no_route", f"{name} has no route to {dst}"))
            return
        nexthops = []  # ECMP routes and recursive resolution can both fan out; dedupe the adjacencies
        for r in routes:
            if r.protocol == "connected":
                out.append(Path(hops + [self._hop(dev, in_if, r.interface)], "delivered"))
                continue
            for out_if, adj in self._res[id(r)]:
                if (out_if, adj) not in nexthops:
                    nexthops.append((out_if, adj))
        for out_if, adj in nexthops:
            hop = self._hop(dev, in_if, out_if)
            owner = self._owner.get(adj) if adj else self._peer_on(dev, out_if)
            if owner is None:
                out.append(Path(hops + [hop], "leaves_model", f"{name} forwards to {adj or out_if}, not a modeled device"))
                continue
            self._walk(owner[0], owner[1], dst, hops + [hop], seen | {name}, out)

    def _peer_on(self, dev: Device, out_if: str) -> tuple[str, str] | None:
        """For an interface route with no next hop: the single other device on that subnet, if any."""
        iface = dev.interface(out_if)
        if iface is None or iface.ip is None:
            return None
        peers = [(d.name, i.name) for d in self.network.devices.values() if d.name != dev.name
                 for i in d.interfaces if i.enabled and i.ip and i.ip.network == iface.ip.network]
        return peers[0] if len(peers) == 1 else None

    # ---- policy ----------------------------------------------------------

    def evaluate(self, device: str, in_zone: str | None, out_zone: str | None, flow: Flow) -> Decision:
        """First matching enabled rule wins; otherwise the device's default action."""
        dev = self.network.devices[device]

        def zone_ok(zones: list[str], zone: str | None) -> bool:
            return ANY in zones or zone in zones

        def addr_ok(names: list[str], ip: IPv4Address) -> bool:
            return ANY in names or any(dev.addresses[n].contains(ip) for n in names)

        def svc_ok(names: list[str]) -> bool:
            return ANY in names or any(dev.services[n].matches(flow.protocol, flow.port) for n in names)

        for p in dev.policies:
            if (p.enabled and zone_ok(p.src_zones, in_zone) and zone_ok(p.dst_zones, out_zone)
                    and addr_ok(p.src_addrs, flow.src) and addr_ok(p.dst_addrs, flow.dst) and svc_ok(p.services)):
                return Decision(p.action, p.name)
        return Decision(dev.default_action, None)

    # ---- analysis --------------------------------------------------------

    def analyze(self, flow: Flow) -> FlowReport:
        rep = FlowReport(flow, self.trace(flow.src, flow.dst), self.trace(flow.dst, flow.src))
        issues: dict[tuple, Issue] = {}

        def add(kind: str, device: str | None, msg: str):
            issues.setdefault((kind, device), Issue(kind, device, msg))

        seen_checks = set()
        for p in rep.forward:
            if not p.delivered and p.status != "leaves_model":
                add(FORWARD_UNREACHABLE, p.hops[-1].device if p.hops else None, p.detail)
            for h in p.hops:
                if not h.is_firewall or h.out_interface is None:
                    continue
                d = self.evaluate(h.device, h.in_zone, h.out_zone, flow)
                if (h.device, h.in_zone, h.out_zone) not in seen_checks:
                    seen_checks.add((h.device, h.in_zone, h.out_zone))
                    rep.checks.append(FirewallCheck(h.device, h.in_zone, h.out_zone, d))
                if d.action == "deny" and d.explicit:
                    add(EXPLICIT_DENY, h.device, f"denied by rule {d.rule!r} ({h.in_zone} -> {h.out_zone})")
                elif d.action == "deny":
                    add(POLICY_DENY, h.device, f"no rule allows {h.in_zone} -> {h.out_zone}; default deny")

        # A return path only matters if the request can arrive, and can only be
        # checked when the destination is inside the modeled network.
        if any(p.status == "leaves_model" for p in rep.forward):
            rep.notes.append("Destination is outside the modeled network (e.g. internet); return path not checked.")
        if not any(p.delivered for p in rep.forward):
            rep.issues = list(issues.values())
            return rep

        for p in rep.reverse:
            if not p.delivered:
                add(REVERSE_UNREACHABLE, p.hops[-1].device if p.hops else None, p.detail)

        # Stateful firewalls need the reply to come back through them. With ECMP the request
        # can take any forward path and the reply any return path, so compare every pair.
        fwd_ok = [p for p in rep.forward if p.delivered]
        rev_ok = [p for p in rep.reverse if p.delivered]
        multi = len(fwd_ok) > 1 or len(rev_ok) > 1
        note = " on at least one of the equal-cost paths" if multi else ""
        for f in fwd_ok:
            for r in rev_ok:
                for fw in sorted(set(f.firewalls) - set(r.firewalls)):
                    add(ASYMMETRIC_BYPASS, fw, f"request crosses {fw} but the reply does not{note}; stateful session breaks")
                for fw in sorted(set(r.firewalls) - set(f.firewalls)):
                    add(ASYMMETRIC_NO_SESSION, fw, f"reply crosses {fw}, which never saw the request{note}; reply is dropped")

        rep.issues = list(issues.values())
        return rep
