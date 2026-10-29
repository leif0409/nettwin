"""Load a snapshot directory (inventory.json + saved config files) into the neutral model.

An inventory entry may also list collected routing-table files ("routes"). When it
does, those routes replace the config's static routes: the device's own routing
table already includes statics plus everything learned from dynamic protocols.
"""
from __future__ import annotations

import json
from pathlib import Path

from twin.drivers import get_driver
from twin.model import Device, Flow, Network
from twin.state import parse_routes


def load_snapshot(path: str | Path) -> Network:
    path = Path(path)
    inventory = json.loads((path / "inventory.json").read_text())
    devices = {}
    for entry in inventory["devices"]:
        device = get_driver(entry["vendor"]).parse((path / entry["file"]).read_text(errors="replace"))
        if device.name in devices:
            raise ValueError(f"duplicate hostname {device.name} in {path}")
        device.vendor_extra["source_file"] = entry["file"]
        for key in ("site", "pos"):
            if key in entry:
                device.vendor_extra[key] = entry[key]
        if entry.get("routes"):
            _apply_state_routes(device, [path / f for f in entry["routes"]])
            device.vendor_extra["routes_files"] = entry["routes"]
        devices[device.name] = device
    return Network(devices=devices)


def _apply_state_routes(device: Device, files: list[Path]) -> None:
    names = {i.name for i in device.interfaces}
    routes, dropped = [], 0
    for f in files:
        parsed = parse_routes(f.read_text(errors="replace"))
        device.unsupported += [f"routing table: skipped {s}" for s in parsed.skipped]
        for r in parsed.routes:
            if r.interface is not None and r.interface not in names:
                if r.next_hop is None:
                    dropped += 1
                    continue
                r = r.model_copy(update={"interface": None})
            routes.append(r)
    if dropped:
        device.unsupported.append(f"routing table: {dropped} interface-only routes on interfaces not in the config")
    device.routes = routes
    device.rib_source = "state"
    # Routing-protocol config is no longer a gap: its outcome is in the imported table.
    protocol_lines = [u for u in device.unsupported if u.startswith(("router ", "protocols "))]
    device.unsupported = [u for u in device.unsupported if u not in protocol_lines]
    if protocol_lines:
        device.vendor_extra["routing_protocols"] = protocol_lines


def load_observed(path: str | Path) -> dict[str, str]:
    """Flow name -> what really happened in a lab ("allowed" / "blocked"), where recorded."""
    return {f.get("name", ""): f["observed"] for f in json.loads(Path(path).read_text()) if "observed" in f}


def load_flows(path: str | Path) -> list[tuple[str, Flow, list[str] | None]]:
    """Returns (name, flow, expected issue kinds or None)."""
    out = []
    for f in json.loads(Path(path).read_text()):
        flow = Flow(src=f["src"], dst=f["dst"], protocol=f["protocol"], port=f.get("port"))
        out.append((f.get("name", str(flow)), flow, f.get("expect")))
    return out
