"""Add / edit / remove devices and snapshots through the API, on a temporary copy of the samples."""
import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from twin import web
from twin.workspace import VENDORS

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


@pytest.fixture
def client(tmp_path, monkeypatch):
    shutil.copytree(SAMPLES / "enterprise", tmp_path / "enterprise")
    monkeypatch.setattr(web, "SAMPLES", tmp_path)
    web._cache.clear()
    yield TestClient(web.app), tmp_path
    web._cache.clear()


def test_every_vendor_example_parses(client):
    c, _ = client
    for vendor in VENDORS:
        r = c.post("/api/enterprise/devices/preview", json={"vendor": vendor, "config": VENDORS[vendor]["example"]})
        assert r.status_code == 200, (vendor, r.json())


def test_add_edit_remove_device(client):
    c, root = client
    r = c.post("/api/enterprise/devices", json={"vendor": "cisco_ios", "config": VENDORS["cisco_ios"]["example"], "site": "Branch 5"})
    assert r.json() == {"name": "BR5"}
    assert (root / "enterprise" / "br5.cfg").is_file()
    assert any(d["name"] == "BR5" and d["site"] == "Branch 5" for d in c.get("/api/enterprise/devices").json())

    # Connect BR5 to WAN-HUB and fix the planted 10.31 typo; the preview reports the impact before saving.
    hub = c.get("/api/enterprise/devices/WAN-HUB").json()["raw"]
    hub = hub.replace("ip route 10.31.0.0 255.255.255.0", "ip route 10.13.0.0 255.255.255.0").replace(
        "interface TenGigabitEthernet1/0", "interface GigabitEthernet0/7\n ip address 172.20.5.2 255.255.255.252\n!\ninterface TenGigabitEthernet1/0")
    p = c.post("/api/enterprise/devices/preview", json={"config": hub, "replacing": "WAN-HUB"}).json()
    assert {"interface": "GigabitEthernet0/7", "subnet": "172.20.5.0/30", "to": "BR5", "to_interface": "GigabitEthernet0/1"} in p["links"]
    assert p["impact"] == [{"name": "br3-to-app-https", "flow": "10.13.0.50 -> 10.100.10.20 tcp/443",
                            "before": ["REVERSE_UNREACHABLE"], "after": []}]
    assert c.put("/api/enterprise/devices/WAN-HUB", json={"config": hub}).status_code == 200

    path = c.get("/api/enterprise/path", params={"src": "10.15.0.50", "dst": "10.100.10.20", "protocol": "tcp", "port": 443}).json()
    assert [h["device"] for h in path["forward"][0]["hops"]][:2] == ["BR5", "WAN-HUB"]

    assert c.delete("/api/enterprise/devices/BR5").status_code == 200
    assert (root / "enterprise" / "_removed" / "br5.cfg").is_file()
    assert "BR5" not in {d["name"] for d in c.get("/api/enterprise/devices").json()}


@pytest.mark.parametrize("vendor,config,msg", [
    ("cisco_ios", "  ", "config is empty"),
    ("cisco_ios", "hostname BR1\ninterface Gi0/0\n ip address 10.99.0.1 255.255.255.0\n", "already exists"),
    ("cisco_ios", "set system host-name X\n", "right vendor"),
    ("panos", "set deviceconfig system hostname Z\nset network interface ethernet ethernet1/1 layer3 ip 10.98.0.1/24\n"
              "set rulebase security rules r1 source ghost\n", "unknown address 'ghost'"),
])
def test_bad_configs_are_refused_without_writing(client, vendor, config, msg):
    c, root = client
    before = sorted(p.name for p in (root / "enterprise").iterdir())
    r = c.post("/api/enterprise/devices", json={"vendor": vendor, "config": config})
    assert r.status_code == 422 and msg in r.json()["detail"]
    assert sorted(p.name for p in (root / "enterprise").iterdir()) == before


def test_duplicate_ip_is_a_warning(client):
    c, _ = client
    p = c.post("/api/enterprise/devices/preview", json={"vendor": "cisco_ios", "config": "hostname DUP\ninterface Gi0/0\n ip address 10.11.0.1 255.255.255.0\n"}).json()
    assert p["warnings"] == ["duplicate IP 10.11.0.1: also on BR1 GigabitEthernet0/0"]


def test_layout_and_snapshots(client):
    c, root = client
    assert c.put("/api/enterprise/layout", json={"positions": {"BR1": [11.4, 22.6]}}).status_code == 200
    assert next(n for n in c.get("/api/enterprise/topology").json()["nodes"] if n["id"] == "BR1")["pos"] == [11, 23]

    assert c.post("/api/snapshots", json={"name": "empty-one"}).status_code == 200
    assert c.get("/api/empty-one/devices").json() == []
    assert c.post("/api/snapshots", json={"name": "copy", "copy_from": "enterprise"}).status_code == 200
    assert len(c.get("/api/copy/devices").json()) == 11
    assert c.post("/api/snapshots", json={"name": "Bad Name!"}).status_code == 422
    assert c.post("/api/snapshots", json={"name": "copy"}).status_code == 422
