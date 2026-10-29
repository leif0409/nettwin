"""Real device data (batfish/lab-validation): routing-table import, recursive next hops, App-ID,
and the twin's predictions scored against traffic that was really sent through the lab devices."""
import importlib.util
from ipaddress import IPv4Address
from pathlib import Path

import pytest

from twin.engine import Twin
from twin.loader import load_flows, load_observed, load_snapshot
from twin.model import Flow
from twin.state import parse_ios_routes, parse_panos_routes

ROOT = Path(__file__).resolve().parent.parent
REAL = ["real-fortigate-policy", "real-paloalto-appid", "real-fortigate-routed", "real-cisco-bgp-ospf"]


@pytest.fixture(scope="module")
def twins():
    return {s: Twin(load_snapshot(ROOT / "samples" / s)) for s in REAL}


@pytest.mark.parametrize("snap", REAL)
def test_baseline_and_real_traffic(snap, twins):
    flows = ROOT / "samples" / snap / "flows.json"
    observed = load_observed(flows)
    for name, f, expect in load_flows(flows):
        rep = twins[snap].analyze(f)
        assert rep.kinds() == sorted(expect), name
        if name in observed:
            assert ("allowed" if rep.ok else "blocked") == observed[name], f"{name}: twin disagrees with the lab"


def test_every_imported_route_resolves(twins):
    assert twins["real-cisco-bgp-ospf"].warnings == []
    dev = twins["real-cisco-bgp-ospf"].network.devices["as2core1"]
    assert dev.rib_source == "state" and {r.protocol for r in dev.routes} == {"ospf", "bgp"}


def test_bgp_next_hop_on_loopback_resolves_recursively(twins):
    tw = twins["real-cisco-bgp-ospf"]
    [r] = [r for r in tw.lookup("as2core1", IPv4Address("2.128.0.5")) if r.protocol == "bgp"]
    assert str(r.next_hop) == "2.34.101.4"  # not directly connected: resolved through OSPF
    assert tw._res[id(r)] == [("GigabitEthernet2/0", IPv4Address("2.23.11.3"))]


def test_ecmp_from_routing_table(twins):
    f = Flow(src="2.128.0.10", dst="3.0.2.10", protocol="icmp")
    paths = twins["real-cisco-bgp-ospf"].trace(f.src, f.dst)
    assert sorted(p.hops[1].device for p in paths) == ["as2dist1", "as2dist2"]


def test_panos_app_id_default_ports(twins):
    fw = twins["real-paloalto-appid"].network.devices["fw"]
    svc = fw.services["app-default:ALLOW"]
    assert svc.matches("tcp", 9100) and svc.matches("udp", 9200) and svc.matches("tcp", 22) and svc.matches("icmp", None)
    assert not svc.matches("tcp", 9101) and not svc.matches("udp", 9201)
    assert fw.unsupported == []


def test_ios_route_parser_formats():
    text = """Gateway of last resort is 10.0.0.1 to network 0.0.0.0

S*    0.0.0.0/0 [1/0] via 10.0.0.1
      10.0.0.0/8 is variably subnetted, 3 subnets, 2 masks
C        10.0.0.0/24 is directly connected, GigabitEthernet0/0
L        10.0.0.2/32 is directly connected, GigabitEthernet0/0
O E2     10.9.0.0/16 [110/20] via 10.0.0.5, 00:01:02, GigabitEthernet0/0
                     [110/20] via 10.0.0.6, 00:01:02, GigabitEthernet0/0
      172.16.0.0/24 is subnetted, 1 subnets
B        172.16.5.0 [20/0] via 192.0.2.1, 00:12:23
S        192.168.0.0/16 is a summary, 00:00:01, Null0
"""
    p = parse_ios_routes(text)
    got = sorted((str(r.prefix), str(r.next_hop), r.protocol) for r in p.routes)
    assert got == [("0.0.0.0/0", "10.0.0.1", "static"), ("10.9.0.0/16", "10.0.0.5", "ospf"),
                   ("10.9.0.0/16", "10.0.0.6", "ospf"), ("172.16.5.0/24", "192.0.2.1", "bgp")]
    assert len(p.skipped) == 1


def test_panos_route_parser_keeps_active_non_connected():
    text = """VIRTUAL ROUTER: default (id 1)
destination        nexthop        metric flags      age   interface          next-AS
0.0.0.0/0          10.0.0.1       10     A S              ethernet1/1
10.5.0.0/16        10.0.0.9       20     A Oi       120   ethernet1/1
10.6.0.0/16        10.0.0.9       20     ? B              ethernet1/1
10.0.0.0/24        10.0.0.2       0      A C              ethernet1/1
"""
    got = [(str(r.prefix), r.protocol, r.interface) for r in parse_panos_routes(text).routes]
    assert got == [("0.0.0.0/0", "static", "ethernet1/1"), ("10.5.0.0/16", "ospf", "ethernet1/1")]


def test_importer_reads_app_id_partial_echo_as_blocked():
    spec = importlib.util.spec_from_file_location("imp", ROOT / "tools" / "import_batfish_lab.py")
    imp = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(imp)
    four_of_eight = "".join(f"packet{i}: x\n" + ("[ECHO:] x\n" if i <= 4 else "") for i in range(1, 9))
    assert imp.observed("udp", four_of_eight) == "blocked"
    assert imp.observed("udp", "packet1: x\n[ECHO:] x\n") == "allowed"
    assert imp.observed("tcp", "Ncat: Connection timed out.\npacket1: x\n[ECHO:] x\n") == "blocked"
    assert imp.observed("icmp", "1 packets transmitted, 1 received, 0% packet loss") == "allowed"
