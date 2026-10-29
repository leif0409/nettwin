"""Load a snapshot directory (inventory.json + saved config files) into the neutral model."""
from __future__ import annotations

import json
from pathlib import Path

from twin.drivers import get_driver
from twin.model import Flow, Network


def load_snapshot(path: str | Path) -> Network:
    path = Path(path)
    inventory = json.loads((path / "inventory.json").read_text())
    devices = {}
    for entry in inventory["devices"]:
        device = get_driver(entry["vendor"]).parse((path / entry["file"]).read_text())
        if device.name in devices:
            raise ValueError(f"duplicate hostname {device.name} in {path}")
        device.vendor_extra["source_file"] = entry["file"]
        for key in ("site", "pos"):
            if key in entry:
                device.vendor_extra[key] = entry[key]
        devices[device.name] = device
    return Network(devices=devices)


def load_flows(path: str | Path) -> list[tuple[str, Flow, list[str] | None]]:
    """Returns (name, flow, expected issue kinds or None)."""
    out = []
    for f in json.loads(Path(path).read_text()):
        flow = Flow(src=f["src"], dst=f["dst"], protocol=f["protocol"], port=f.get("port"))
        out.append((f.get("name", str(flow)), flow, f.get("expect")))
    return out
