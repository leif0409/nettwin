"""Rule recommender safety rules and a smoke test of the web API."""
from fastapi.testclient import TestClient

from twin.model import Flow
from twin.recommend import recommend
from twin.web import app


def flow(src, dst, port=443):
    return Flow(src=src, dst=dst, protocol="tcp", port=port)


def test_default_deny_gets_vendor_rule_that_validates(twin):
    rec = recommend(twin, twin.analyze(flow("10.1.10.50", "10.3.30.10", 5432)))
    [rule] = rec.rules
    assert rule.device == "FW2" and 'set srcintf "port1"' in rule.rendered
    assert rec.validated


def test_two_firewalls_two_vendor_rules(ent):
    rec = recommend(ent, ent.analyze(flow("10.1.10.50", "10.200.0.15", 8443)))
    assert [r.device for r in rec.rules] == ["HQ-FW", "INET-FW"]
    assert all(r.rendered.startswith("set address") for r in rec.rules)
    assert rec.validated


def test_explicit_deny_is_never_overridden(twin):
    rec = recommend(twin, twin.analyze(flow("10.1.10.50", "10.2.20.10", 23)))
    assert rec.rules == [] and "EXPLICIT_DENY" in rec.blockers[0]


def test_routing_problem_blocks_rule_proposal(twin):
    rec = recommend(twin, twin.analyze(flow("10.1.10.200", "10.2.20.10")))
    assert rec.rules == [] and "ASYMMETRIC_BYPASS" in rec.blockers[0]


def test_original_model_untouched_by_validation(twin):
    before = len(twin.network.devices["FW2"].policies)
    recommend(twin, twin.analyze(flow("10.1.10.50", "10.3.30.10", 5432)))
    assert len(twin.network.devices["FW2"].policies) == before


def test_api_smoke():
    c = TestClient(app)
    assert {s["name"] for s in c.get("/api/snapshots").json()} >= {"lab1", "enterprise"}
    topo = c.get("/api/enterprise/topology").json()
    assert len([n for n in topo["nodes"] if n["kind"] != "subnet"]) == 11
    r = c.get("/api/enterprise/path", params={"src": "10.1.20.40", "dst": "10.100.30.5", "protocol": "tcp", "port": 22}).json()
    assert [i["kind"] for i in r["issues"]] == ["ASYMMETRIC_NO_SESSION"]
    assert all(e in {x["id"] for x in topo["edges"]} for p in r["forward"] for e in p["edges"])
    assert c.get("/api/enterprise/path", params={"src": "bad", "dst": "10.0.0.1"}).status_code == 422
    assert c.get("/api/enterprise/devices/NOPE").status_code == 404
    assert c.get("/").status_code == 200
