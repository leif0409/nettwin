"""NetTwin web app: FastAPI JSON API over the engine, plus the static single-page UI.

Run:  .venv\\Scripts\\python.exe -m uvicorn twin.web:app --port 8000
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from ipaddress import IPv4Address
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ValidationError

from twin import workspace
from twin.drivers import get_driver
from twin.engine import FlowReport, Path as TwinPath, Twin
from twin.loader import load_flows, load_snapshot
from twin.model import Flow, Network
from twin.recommend import Recommendation, recommend
from twin.topology import Topology, build_topology

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples"
STATIC = ROOT / "static"


@dataclass
class Snapshot:
    name: str
    path: Path
    network: Network
    twin: Twin
    topology: Topology


_cache: dict[str, Snapshot] = {}


def snapshot(name: str) -> Snapshot:
    if name not in _cache:
        path = SAMPLES / name
        if not (path / "inventory.json").is_file():
            raise HTTPException(404, f"no snapshot {name!r}")
        net = load_snapshot(path)
        _cache[name] = Snapshot(name, path, net, Twin(net), build_topology(net))
    return _cache[name]


def snapshot_names() -> list[str]:
    return sorted(p.name for p in SAMPLES.iterdir() if (p / "inventory.json").is_file())


# ---- serialization ----------------------------------------------------------

def path_dict(p: TwinPath, snap: Snapshot) -> dict:
    edges = []
    for h in p.hops:
        for iface in (h.in_interface, h.out_interface):
            eid = snap.topology.edge_of.get((h.device, iface)) if iface else None
            if eid and eid not in edges:
                edges.append(eid)
    return {
        "status": p.status, "detail": p.detail, "delivered": p.delivered, "edges": edges,
        "hops": [{
            "device": h.device, "in_interface": h.in_interface, "out_interface": h.out_interface,
            "in_zone": h.in_zone, "out_zone": h.out_zone, "is_firewall": h.is_firewall,
            "vendor": snap.network.devices[h.device].vendor,
        } for h in p.hops],
    }


def report_dict(rep: FlowReport, rec: Recommendation | None, snap: Snapshot) -> dict:
    out = {
        "flow": {"src": str(rep.flow.src), "dst": str(rep.flow.dst), "protocol": rep.flow.protocol,
                 "port": rep.flow.port, "text": str(rep.flow)},
        "ok": rep.ok,
        "forward": [path_dict(p, snap) for p in rep.forward],
        "reverse": [path_dict(p, snap) for p in rep.reverse],
        "checks": [{"device": c.device, "in_zone": c.in_zone, "out_zone": c.out_zone,
                    "action": c.decision.action, "rule": c.decision.rule} for c in rep.checks],
        "issues": [{"kind": i.kind, "device": i.device, "message": i.message} for i in rep.issues],
        "notes": rep.notes,
    }
    if rec is not None:
        out["recommendation"] = {
            "blockers": rec.blockers,
            "validated": rec.validated,
            "after_issues": rec.after.kinds() if rec.after else None,
            "rules": [{"device": r.device, "vendor": r.vendor, "rendered": r.rendered, "name": r.request.name,
                       "src_zone": r.request.src_zone, "dst_zone": r.request.dst_zone} for r in rec.rules],
        }
    return out


# ---- app --------------------------------------------------------------------

app = FastAPI(title="NetTwin", version="0.1")


@app.middleware("http")
async def no_cache(request, call_next):
    # Prototype: always serve fresh UI files so edits show up on reload.
    resp = await call_next(request)
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.get("/api/snapshots")
def api_snapshots():
    out = []
    for name in snapshot_names():
        s = snapshot(name)
        inventory = json.loads((s.path / "inventory.json").read_text())
        out.append({"name": name, "devices": len(s.network.devices), "description": inventory.get("description", "")})
    return out


@app.get("/api/{snap}/topology")
def api_topology(snap: str):
    s = snapshot(snap)
    return {"nodes": s.topology.nodes, "edges": s.topology.edges}


@app.get("/api/{snap}/devices")
def api_devices(snap: str):
    s = snapshot(snap)
    out = []
    for d in s.network.devices.values():
        out.append({
            "name": d.name, "vendor": d.vendor, "role": d.role, "site": d.vendor_extra.get("site", ""),
            "interfaces": len(d.interfaces), "up_interfaces": sum(i.enabled for i in d.interfaces),
            "routes": len(s.twin._rib[d.name]), "policies": len(d.policies),
            "unsupported": len(d.unsupported),
            "mgmt": next((str(i.ip.ip) for i in d.interfaces if i.enabled and i.ip), ""),
        })
    return out


@app.get("/api/{snap}/devices/{name}")
def api_device(snap: str, name: str):
    s = snapshot(snap)
    d = s.network.devices.get(name)
    if d is None:
        raise HTTPException(404, f"no device {name!r}")
    rib = s.twin._rib[name]
    routes = [{"prefix": str(r.prefix), "next_hop": str(r.next_hop) if r.next_hop else "", "interface": r.interface or "",
               "protocol": r.protocol, "admin_distance": r.admin_distance, "vrf": r.vrf,
               "installed": any(r is x for x in rib)} for r in d.connected_routes() + d.routes]
    for r in routes:
        if r["protocol"] == "connected":
            r["installed"] = True
    raw = (s.path / d.vendor_extra["source_file"]).read_text()
    return {
        "name": d.name, "vendor": d.vendor, "role": d.role, "site": d.vendor_extra.get("site", ""),
        "source_file": d.vendor_extra["source_file"], "default_action": d.default_action,
        "interfaces": [{"name": i.name, "ip": str(i.ip) if i.ip else "", "zone": i.zone or "", "vrf": i.vrf,
                        "enabled": i.enabled, "description": i.description,
                        "neighbor": _neighbor(s, d.name, i.name)} for i in d.interfaces],
        "routes": routes,
        "policies": [p.model_dump() for p in d.policies],
        "addresses": [{"name": a.name, "prefixes": [str(p) for p in a.prefixes]} for a in sorted(d.addresses.values(), key=lambda a: a.name)],
        "services": [{"name": sv.name, "entries": [
            {"protocol": e.protocol, "ports": ",".join(f"{r.start}" if r.start == r.end else f"{r.start}-{r.end}" for r in e.ports) or "any"}
            for e in sv.entries]} for sv in sorted(d.services.values(), key=lambda x: x.name)],
        "unsupported": d.unsupported,
        "warnings": [w for w in s.twin.warnings if w.startswith(f"{name}:")],
        "raw": raw,
    }


def _neighbor(s: Snapshot, dev: str, iface: str) -> str:
    eid = s.topology.edge_of.get((dev, iface))
    if not eid:
        return ""
    e = next(e for e in s.topology.edges if e["id"] == eid)
    if e["target"].startswith("net:"):
        return f"LAN {e['subnet']}"
    other, oif = (e["target"], e["target_if"]) if e["source"] == dev else (e["source"], e["source_if"])
    return f"{other} {oif}"


@app.get("/api/{snap}/path")
def api_path(snap: str, src: str, dst: str, protocol: str = "tcp", port: int | None = None):
    s = snapshot(snap)
    try:
        flow = Flow(src=src, dst=dst, protocol=protocol, port=port)
    except ValidationError as e:
        raise HTTPException(422, "; ".join(err["msg"] for err in e.errors())) from None
    rep = s.twin.analyze(flow)
    return report_dict(rep, recommend(s.twin, rep), s)


@app.get("/api/{snap}/checks")
def api_checks(snap: str):
    s = snapshot(snap)
    flows_file = s.path / "flows.json"
    results = []
    if flows_file.is_file():
        for name, flow, expect in load_flows(flows_file):
            rep = s.twin.analyze(flow)
            got = rep.kinds()
            results.append({"name": name, "src": str(flow.src), "dst": str(flow.dst), "protocol": flow.protocol,
                            "port": flow.port, "flow": str(flow), "ok": rep.ok, "issues": got,
                            "expect": sorted(expect) if expect is not None else None,
                            "matches": expect is None or got == sorted(expect)})
    findings = []
    for d in s.network.devices.values():
        findings += [{"severity": "info", "device": d.name, "category": "Not modeled", "message": u} for u in d.unsupported]
        findings += [{"severity": "low", "device": d.name, "category": "Disabled rule", "message": f"rule {p.name!r} is disabled"}
                     for p in d.policies if not p.enabled]
        findings += [{"severity": "medium", "device": d.name, "category": "Interface down",
                      "message": f"{i.name} {i.ip or ''} is administratively down"} for i in d.interfaces if not i.enabled]
    for w in s.twin.warnings:
        dev, _, msg = w.partition(": ")
        findings.append({"severity": "high", "device": dev, "category": "Route not installed", "message": msg})
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    findings.sort(key=lambda f: (order[f["severity"]], f["device"]))
    return {"flows": results, "findings": findings}


@app.get("/api/{snap}/search")
def api_search(snap: str, q: str):
    s = snapshot(snap)
    q = q.strip()
    hits: list[dict] = []
    try:
        ip = IPv4Address(q)
    except ValueError:
        ip = None
    for d in s.network.devices.values():
        if ip is None and q.lower() in d.name.lower():
            hits.append({"type": "Device", "device": d.name, "detail": f"{d.vendor} {d.role}"})
        for i in d.interfaces:
            if i.ip is None:
                continue
            if ip is not None and i.ip.ip == ip:
                hits.append({"type": "Interface IP", "device": d.name, "detail": f"{i.name} owns {i.ip}"})
            elif ip is not None and ip in i.ip.network:
                hits.append({"type": "Connected subnet", "device": d.name, "detail": f"{i.name} {i.ip.network} (first hop for this host)"})
            elif ip is None and (q in str(i.ip) or q.lower() in i.name.lower() or q.lower() in i.description.lower()):
                hits.append({"type": "Interface", "device": d.name, "detail": f"{i.name} {i.ip} {i.description}"})
        for a in d.addresses.values():
            if (ip is not None and a.contains(ip) and a.name != "all") or (ip is None and q.lower() in a.name.lower()):
                hits.append({"type": "Address object", "device": d.name, "detail": f"{a.name} = {', '.join(map(str, a.prefixes)) or '(unresolved)'}"})
        for p in d.policies:
            if ip is None and q.lower() in p.name.lower():
                hits.append({"type": "Policy", "device": d.name, "detail": f"{p.name} ({p.action})"})
        if ip is not None:
            best = s.twin.lookup(d.name, ip)
            if best and best[0].protocol != "connected":
                r = best[0]
                hits.append({"type": "Route lookup", "device": d.name,
                             "detail": f"{r.prefix} via {r.next_hop or r.interface}" + (f" (+{len(best)-1} ECMP)" if len(best) > 1 else "")})
    order = ["Interface IP", "Connected subnet", "Device", "Interface", "Address object", "Policy", "Route lookup"]
    hits.sort(key=lambda h: order.index(h["type"]))
    return {"query": q, "is_ip": ip is not None, "hits": hits}


# ---- editing ----------------------------------------------------------------

class DeviceIn(BaseModel):
    vendor: str | None = None
    config: str
    site: str | None = None
    replacing: str | None = None


class SnapshotIn(BaseModel):
    name: str
    description: str = ""
    copy_from: str | None = None


class LayoutIn(BaseModel):
    positions: dict[str, list[float]]


@app.exception_handler(workspace.ChangeError)
def change_error(_request, exc: workspace.ChangeError):
    return JSONResponse(status_code=422, content={"detail": str(exc)})


def _changed(snap: str) -> None:
    _cache.pop(snap, None)


@app.get("/api/vendors")
def api_vendors():
    return [{"id": k, "label": v["label"], "role": get_driver(k).role, "example": v["example"]} for k, v in workspace.VENDORS.items()]


@app.post("/api/snapshots")
def api_create_snapshot(body: SnapshotIn):
    workspace.create_snapshot(SAMPLES, body.name, body.description, body.copy_from)
    return {"name": body.name}


@app.post("/api/{snap}/devices/preview")
def api_preview_device(snap: str, body: DeviceIn):
    s = snapshot(snap)
    vendor = body.vendor
    if body.replacing:
        if body.replacing not in s.network.devices:
            raise HTTPException(404, f"no device {body.replacing!r}")
        vendor = s.network.devices[body.replacing].vendor
    return workspace.preview(s.path, s.network, vendor or "", body.config, body.replacing)


@app.post("/api/{snap}/devices")
def api_add_device(snap: str, body: DeviceIn):
    s = snapshot(snap)
    name = workspace.add_device(s.path, s.network, body.vendor or "", body.config, body.site or "")
    _changed(snap)
    return {"name": name}


@app.put("/api/{snap}/devices/{name}")
def api_update_device(snap: str, name: str, body: DeviceIn):
    s = snapshot(snap)
    new_name = workspace.update_device(s.path, s.network, name, body.config, body.site)
    _changed(snap)
    return {"name": new_name}


@app.delete("/api/{snap}/devices/{name}")
def api_remove_device(snap: str, name: str):
    s = snapshot(snap)
    workspace.remove_device(s.path, s.network, name)
    _changed(snap)
    return {"removed": name}


@app.put("/api/{snap}/layout")
def api_layout(snap: str, body: LayoutIn):
    s = snapshot(snap)
    workspace.save_layout(s.path, s.network, body.positions)
    _changed(snap)
    return {"saved": len(body.positions)}


app.mount("/static", StaticFiles(directory=STATIC), name="static")


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")
