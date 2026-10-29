"""Platform behaviour found in real configs: NX-OS / Junos routing tables, HSRP/VRRP gateways,
management VRFs, switches, and the synthetic two-region global-corp lab."""
import json
from pathlib import Path

import pytest

from twin.drivers import get_driver
from twin.engine import Twin
from twin.loader import load_flows, load_snapshot
from twin.model import Device, Flow, Interface, Network
from twin.state import parse_ios_routes, parse_junos_json_routes, parse_nxos_routes
from twin.topology import build_topology

ROOT = Path(__file__).resolve().parent.parent

# Shapes taken from real captures in batfish/lab-validation (mix_vendor_bgp_vrf)
NXOS_ROUTES = """IP Route Table for VRF "default"
'*' denotes best ucast next-hop
'**' denotes best mcast next-hop
'[x/y]' denotes [preference/metric]
'%<string>' in via output denotes VRF <string>

10.10.10.0/24, ubest/mbest: 1/0
    *via 10.10.20.1, [20/0], 5d07h, bgp-20, external, tag 1
10.10.20.0/24, ubest/mbest: 1/0, attached
    *via 10.10.20.2, Eth1/1, [0/0], 5d07h, direct
10.10.20.2/32, ubest/mbest: 1/0, attached
    *via 10.10.20.2, Eth1/1, [0/0], 5d07h, local
10.20.0.0/16, ubest/mbest: 2/0
    *via 172.16.3.0, Eth1/49, [110/41], 3w2d, ospf-UNDERLAY, intra
    *via 172.16.3.8, Eth1/50, [110/41], 3w2d, ospf-UNDERLAY, intra

IP Route Table for VRF "management"
0.0.0.0/0, ubest/mbest: 1/0
    *via 192.168.10.1, [1/0], 3w2d, static
"""


def test_nxos_routes():
    got = sorted((r.vrf, str(r.prefix), str(r.next_hop), r.protocol) for r in parse_nxos_routes(NXOS_ROUTES).routes)
    assert got == [("default", "10.10.10.0/24", "10.10.20.1", "bgp"), ("default", "10.20.0.0/16", "172.16.3.0", "ospf"),
                   ("default", "10.20.0.0/16", "172.16.3.8", "ospf"), ("management", "0.0.0.0/0", "192.168.10.1", "static")]


def test_junos_json_routes_with_trailing_prompt():
    def data(v):
        return [{"data": v}]
    doc = {"route-information": [{"route-table": [{"table-name": data("inet.0"), "rt": [
        {"rt-destination": data("10.10.10.0/24"), "rt-entry": [{"active-tag": data("*"), "protocol-name": data("BGP"),
          "preference": data("170"), "nh": [{"selected-next-hop": [{"data": [None]}], "to": data("10.10.50.1"), "via": data("xe-0/0/0.0")}]}]},
        {"rt-destination": data("10.10.50.0/24"), "rt-entry": [{"active-tag": data("*"), "protocol-name": data("Direct"),
          "preference": data("0"), "nh": [{"via": data("xe-0/0/0.0")}]}]},
        {"rt-destination": data("10.99.0.0/16"), "rt-entry": [{"active-tag": data("*"), "protocol-name": data("Static"),
          "preference": data("5"), "nh-type": data("Discard")}]},
    ]}]}]}
    p = parse_junos_json_routes(json.dumps(doc, indent=4) + "\n\n{master:0}\n")
    assert [(str(r.prefix), str(r.next_hop), r.interface, r.protocol) for r in p.routes] == [("10.10.10.0/24", "10.10.50.1", "xe-0/0/0.0", "bgp")]
    assert len(p.skipped) == 1


def test_ios_default_route_codes_without_space():
    p = parse_ios_routes("O*E2  0.0.0.0/0 [110/1] via 10.0.0.1, 00:01:02, Gi0/0\nD*EX  0.0.0.0/0 [170/2] via 10.0.0.9, 00:01:02, Gi0/1\n")
    assert [(str(r.prefix), r.protocol) for r in p.routes] == [("0.0.0.0/0", "ospf"), ("0.0.0.0/0", "eigrp")]


def test_nxos_config_vrf_member_and_context_routes():
    dev = get_driver("cisco_nxos").parse(
        "hostname leaf1\nfeature interface-vlan\nvrf context management\n  ip route 0.0.0.0/0 192.168.10.1\n\n"
        "interface Vlan110\n  ip address 10.1.10.1/24\n  hsrp 110\n    priority 110\n    ip 10.1.10.254\n\n"
        "interface mgmt0\n  vrf member management\n  ip address 192.168.10.21/24\n")
    assert dev.role == "switch" and dev.vendor == "cisco_nxos"
    assert dev.interface("mgmt0").vrf == "management"
    assert (str(dev.interface("Vlan110").vip), dev.interface("Vlan110").fhrp_priority) == ("10.1.10.254", 110)
    assert [(r.vrf, str(r.next_hop)) for r in dev.routes] == [("management", "192.168.10.1")]


def test_ios_hsrp_default_gateway_and_null_routes():
    dev = get_driver("cisco_ios").parse(
        "hostname acc1\nno ip routing\nspanning-tree mode rapid-pvst\ninterface Vlan99\n ip address 10.2.99.11 255.255.255.0\n!\n"
        "ip default-gateway 10.2.99.1\nip route 10.0.0.0 255.0.0.0 Null0\n")
    assert dev.role == "switch"
    assert [(str(r.prefix), str(r.next_hop)) for r in dev.routes] == [("0.0.0.0/0", "10.2.99.1")]
    assert any("Null0" in u for u in dev.unsupported)


def _hsrp_pair(prio_a: int, prio_b: int) -> Twin:
    def dev(name, ip, prio):
        return Device(name=name, vendor="t", role="switch",
                      interfaces=[Interface(name="Vlan10", ip=f"10.0.10.{ip}/24", vip="10.0.10.1", fhrp_priority=prio)])
    return Twin(Network(devices={"a": dev("a", 2, prio_a), "b": dev("b", 3, prio_b)}))


@pytest.mark.parametrize("pa,pb,active", [(110, 100, "a"), (100, 110, "b"), (100, 100, "b")])  # tie: highest IP wins
def test_hsrp_active_member_is_the_only_ingress(pa, pb, active):
    tw = _hsrp_pair(pa, pb)
    assert tw.ingress_for(Flow(src="10.0.10.50", dst="1.1.1.1", protocol="icmp").src) == [(active, "Vlan10")]
    assert tw._owner[Flow(src="10.0.10.1", dst="1.1.1.1", protocol="icmp").src][0] == active


def test_management_vrf_not_drawn():
    topo = build_topology(load_snapshot(ROOT / "samples" / "global-corp"))
    assert not any(n["id"].startswith("net:192.168.") for n in topo.nodes)


@pytest.fixture(scope="module")
def corp():
    return Twin(load_snapshot(ROOT / "samples" / "global-corp"))


def test_global_corp_loads_cleanly(corp):
    devs = corp.network.devices.values()
    assert len(devs) == 35
    assert {d.vendor for d in devs} == {"cisco_ios", "cisco_nxos", "junos", "panos", "fortios"}
    assert sum(d.role == "firewall" for d in devs) == 7
    assert corp.warnings == []  # every imported route resolves
    assert not any(u.startswith("unparsed") for d in devs for u in d.unsupported)


def test_global_corp_flows_match_design_intent(corp):
    for name, f, expect in load_flows(ROOT / "samples" / "global-corp" / "flows.json"):
        assert corp.analyze(f).kinds() == sorted(expect), name


def test_global_corp_planted_asymmetry_is_at_the_hq_firewall(corp):
    rep = corp.analyze(Flow(src="10.2.10.50", dst="10.33.20.20", protocol="tcp", port=443))
    assert [(i.kind, i.device) for i in rep.issues] == [("ASYMMETRIC_NO_SESSION", "na-hq-fw1")]
    assert {p.hops[0].device for p in rep.forward} == {"na-hq-core2"}  # HSRP-active for the users VLAN


def test_generator_is_deterministic(tmp_path):
    import subprocess
    import sys
    subprocess.run([sys.executable, str(ROOT / "tools" / "gen_global_lab.py"), str(tmp_path)], check=True, capture_output=True)
    for f in tmp_path.rglob("*"):
        if f.is_file():
            assert f.read_bytes() == (ROOT / "samples" / "global-corp" / f.relative_to(tmp_path)).read_bytes(), f
