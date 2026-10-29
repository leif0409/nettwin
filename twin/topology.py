"""Derive L3 topology from the model: devices sharing a connected subnet are linked;
a subnet attached to only one device becomes an endpoint (LAN) node."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from ipaddress import IPv4Network

from twin.model import MANAGEMENT_VRFS, Network


@dataclass
class Topology:
    nodes: list[dict] = field(default_factory=list)
    edges: list[dict] = field(default_factory=list)
    # (device, interface) -> edge id, so a path hop maps straight onto the map
    edge_of: dict[tuple[str, str], str] = field(default_factory=dict)


def subnet_id(net: IPv4Network) -> str:
    return f"net:{net}"


def build_topology(network: Network) -> Topology:
    topo = Topology()
    attached: dict[IPv4Network, list[tuple[str, str]]] = defaultdict(list)
    fhrp_lans: set[IPv4Network] = set()  # subnets with an HSRP/VRRP gateway: a LAN, not a link
    for dev in network.devices.values():
        topo.nodes.append({
            "id": dev.name, "kind": dev.role, "vendor": dev.vendor,
            "site": dev.vendor_extra.get("site", ""), "pos": dev.vendor_extra.get("pos"),
        })
        for i in dev.interfaces:
            # Out-of-band management ports would tie every device to one segment; leave them off the map.
            if i.enabled and i.ip is not None and i.vrf.lower() not in MANAGEMENT_VRFS:
                attached[i.ip.network].append((dev.name, i.name))
                if i.vip is not None:
                    fhrp_lans.add(i.ip.network)

    for net, ends in sorted(attached.items()):
        if net.prefixlen == 32 and len(ends) == 1:
            continue  # a loopback: an address on the device, not something to draw
        # One device: an edge LAN. Three or more: a shared segment (a switch/VLAN between them),
        # drawn as one node rather than a full mesh of links.
        if len({d for d, _ in ends}) != 2 or net in fhrp_lans:
            node = {"id": subnet_id(net), "kind": "subnet", "label": str(net), "attached_to": ends[0][0]}
            if len(ends) > 1:
                node["segment"] = True
            topo.nodes.append(node)
            for dev, iface in ends:
                eid = f"{dev}:{iface}|{subnet_id(net)}"
                topo.edges.append({"id": eid, "source": dev, "target": subnet_id(net),
                                   "source_if": iface, "target_if": "", "subnet": str(net)})
                topo.edge_of[(dev, iface)] = eid
            continue
        for a in range(len(ends)):
            for b in range(a + 1, len(ends)):
                (da, ia), (db, ib) = sorted([ends[a], ends[b]])
                eid = f"{da}:{ia}|{db}:{ib}"
                topo.edges.append({"id": eid, "source": da, "target": db,
                                   "source_if": ia, "target_if": ib, "subnet": str(net)})
                topo.edge_of[(da, ia)] = eid
                topo.edge_of[(db, ib)] = eid
    return topo
