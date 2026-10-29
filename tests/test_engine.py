"""Path engine, policy and asymmetry checks, plus the saved-flow baselines for both snapshots."""
from pathlib import Path

import pytest

from twin.engine import Twin
from twin.loader import load_flows
from twin.model import Device, Flow, Interface, Network, Route

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def flow(src, dst, proto="tcp", port=443):
    return Flow(src=src, dst=dst, protocol=proto, port=port)


@pytest.mark.parametrize("snap", ["lab1", "enterprise"])
def test_saved_flows_match_baseline(snap, request):
    twin = request.getfixturevalue("twin" if snap == "lab1" else "ent")
    for name, f, expect in load_flows(SAMPLES / snap / "flows.json"):
        assert twin.analyze(f).kinds() == sorted(expect), name


def test_forward_path_hops(twin):
    [p] = twin.trace(flow("10.1.10.50", "10.2.20.10").src, flow("10.1.10.50", "10.2.20.10").dst)
    assert [h.device for h in p.hops] == ["R1", "FW1", "CORE"]
    assert p.delivered and p.firewalls == ["FW1"]


def test_floating_route_not_used_while_primary_up(twin):
    [r] = twin.lookup("R1", flow("10.1.10.50", "8.8.8.8").dst)
    assert str(r.next_hop) == "172.16.1.2"


def test_route_via_down_interface_not_installed(twin):
    assert any("198.51.100.0/24 not installed" in w for w in twin.warnings)


def test_asymmetric_bypass_names_firewall(twin):
    rep = twin.analyze(flow("10.1.10.200", "10.2.20.10"))
    assert [(i.kind, i.device) for i in rep.issues] == [("ASYMMETRIC_BYPASS", "FW1")]


def test_loop_detected(twin):
    paths = twin.trace(flow("10.1.10.50", "10.5.50.10").src, flow("10.1.10.50", "10.5.50.10").dst)
    assert [p.status for p in paths] == ["loop"]


def test_ecmp_in_enterprise(ent):
    f = flow("10.11.0.50", "10.100.10.20")
    paths = ent.trace(f.src, f.dst)
    assert sorted(p.hops[2].device for p in paths) == ["DC-CORE1", "DC-CORE2"]
    assert all(p.delivered for p in paths)


def test_internet_destination_exits_model(ent):
    rep = ent.analyze(flow("10.1.10.50", "8.8.8.8"))
    assert rep.ok and rep.forward[0].status == "leaves_model" and rep.notes


def test_ecmp_and_vrf_on_synthetic_model():
    def dev(name, ifs, routes):
        return Device(name=name, vendor="test", role="router",
                      interfaces=[Interface(name=n, ip=ip, vrf=v) for n, ip, v in ifs], routes=routes)

    net = Network(devices={
        "A": dev("A", [("lan", "10.0.0.1/24", "default"), ("b", "192.168.1.1/30", "default"),
                       ("c", "192.168.2.1/30", "default"), ("red", "10.0.0.1/24", "RED")],
                 [Route(prefix="10.9.0.0/24", next_hop="192.168.1.2", admin_distance=1),
                  Route(prefix="10.9.0.0/24", next_hop="192.168.2.2", admin_distance=1)]),
        "B": dev("B", [("a", "192.168.1.2/30", "default"), ("lan", "10.9.0.1/24", "default")], []),
        "C": dev("C", [("a", "192.168.2.2/30", "default"), ("lan", "10.9.0.2/24", "default")], []),
    })
    t = Twin(net)
    assert len(t.lookup("A", flow("10.0.0.5", "10.9.0.9").dst)) == 2
    assert t.lookup("A", flow("10.0.0.5", "10.9.0.9").dst, vrf="RED") == []
