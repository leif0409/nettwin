"""Derive L3 topology from the model: devices sharing a connected subnet are linked;
a subnet attached to only one device becomes an endpoint (LAN) node."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from ipaddress import IPv4Network

from twin.model import Network


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
    for dev in network.devices.values():
        topo.nodes.append({
            "id": dev.name, "kind": dev.role, "vendor": dev.vendor,
            "site": dev.vendor_extra.get("site", ""), "pos": dev.vendor_extra.get("pos"),
        })
        for i in dev.interfaces:
            if i.enabled and i.ip is not None:
                attached[i.ip.network].append((dev.name, i.name))

    for net, ends in sorted(attached.items()):
        if len({d for d, _ in ends}) == 1:
            dev, iface = ends[0]
            eid = f"{dev}:{iface}|{subnet_id(net)}"
            topo.nodes.append({"id": subnet_id(net), "kind": "subnet", "label": str(net), "attached_to": dev})
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
