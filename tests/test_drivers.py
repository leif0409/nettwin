"""Contract tests: each driver turns its vendor's config into the expected neutral objects."""
from ipaddress import IPv4Address, IPv4Network

import pytest
from pydantic import ValidationError

from twin.drivers import get_driver


def test_all_four_vendors_load(lab1):
    assert {d.name: d.vendor for d in lab1.devices.values()} == {
        "R1": "cisco_ios", "CORE": "junos", "FW1": "panos", "FW2": "fortios",
    }


def test_ios_interfaces_and_shutdown(lab1):
    r1 = lab1.devices["R1"]
    assert str(r1.interface("GigabitEthernet0/0").ip) == "10.1.10.1/24"
    assert r1.interface("GigabitEthernet0/3").enabled is False


def test_ios_admin_distance(lab1):
    defaults = sorted((r.admin_distance, str(r.next_hop)) for r in lab1.devices["R1"].routes
                      if r.prefix == IPv4Network("0.0.0.0/0"))
    assert defaults == [(1, "172.16.1.2"), (250, "172.16.9.2")]


def test_ios_route_with_interface_and_vrf():
    dev = get_driver("cisco_ios").parse(
        "hostname X\ninterface Gi0/1\n vrf forwarding RED\n ip address 10.0.0.1 255.255.255.0\n!\n"
        "ip route vrf RED 10.9.0.0 255.255.0.0 Gi0/1 10.0.0.2 20\n"
    )
    r = dev.routes[0]
    assert (r.vrf, r.interface, str(r.next_hop), r.admin_distance) == ("RED", "Gi0/1", "10.0.0.2", 20)


def test_junos_units_and_default_preference(lab1):
    core = lab1.devices["CORE"]
    assert str(core.interface("ge-0/0/2.0").ip) == "10.2.20.1/24"
    assert {r.admin_distance for r in core.routes} == {5}


def test_junos_multiple_next_hops_are_ecmp():
    dev = get_driver("junos").parse(
        "set system host-name J\n"
        "set routing-options static route 10.0.0.0/8 next-hop 1.1.1.1\n"
        "set routing-options static route 10.0.0.0/8 next-hop 2.2.2.2\n"
    )
    assert sorted(str(r.next_hop) for r in dev.routes) == ["1.1.1.1", "2.2.2.2"]


def test_panos_zones_objects_and_rule_order(lab1):
    fw1 = lab1.devices["FW1"]
    assert fw1.interface("ethernet1/1").zone == "trust"
    assert fw1.addresses["db-vip"].prefixes == [IPv4Network("10.3.30.10/31"), IPv4Network("10.3.30.12/32")]
    assert fw1.addresses["db-all"].contains(IPv4Address("10.3.30.200"))
    assert [p.name for p in fw1.policies] == ["block-telnet", "users-to-app", "users-to-db"]
    assert fw1.services["web"].matches("tcp", 8090) and not fw1.services["web"].matches("tcp", 8091)


def test_panos_flags_application_match(lab1):
    assert any("application match" in u for u in lab1.devices["FW1"].unsupported)


def test_fortios_zones_and_disabled_policy(lab1, ent):
    fw2 = lab1.devices["FW2"]
    assert fw2.interface("port1").zone == "port1"  # no zone configured: interface is its own zone
    assert [p.enabled for p in fw2.policies] == [True, False]
    dcfw = ent.network.devices["DC-FW"]
    assert dcfw.interface("port2").zone == "outside"


def test_unknown_object_reference_fails_loudly():
    with pytest.raises(ValidationError, match="unknown address 'ghost'"):
        get_driver("panos").parse(
            "set deviceconfig system hostname BAD\n"
            "set rulebase security rules r1 source ghost\n"
            "set rulebase security rules r1 action allow\n"
        )


def test_host_bits_in_prefix_fail_loudly():
    with pytest.raises(ValidationError):
        get_driver("junos").parse("set system host-name J\nset routing-options static route 10.0.0.1/8 next-hop 1.1.1.1\n")
