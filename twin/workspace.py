"""Editing snapshots on disk: add, replace and remove device configs, create snapshots, save map layout.

Every change is parsed and checked before anything is written. Removed configs
are moved to <snapshot>/_removed/ instead of being deleted.
"""
from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

from pydantic import ValidationError

from twin.drivers import DRIVERS, get_driver
from twin.engine import Twin
from twin.loader import load_flows, load_snapshot
from twin.model import Device, Network
from twin.topology import build_topology

SNAPSHOT_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{0,40}$")

VENDORS = {
    "cisco_ios": {"label": "Cisco IOS / IOS-XE", "ext": ".cfg", "example": """hostname BR5
!
interface GigabitEthernet0/0
 description BR5-USERS
 ip address 10.15.0.1 255.255.255.0
!
interface GigabitEthernet0/1
 description WAN-TO-HUB
 ip address 172.20.5.1 255.255.255.252
!
ip route 0.0.0.0 0.0.0.0 172.20.5.2
!
end
"""},
    "junos": {"label": "Juniper Junos (display set)", "ext": ".conf", "example": """set system host-name BR6
set interfaces ge-0/0/0 unit 0 family inet address 10.16.0.1/24
set interfaces ge-0/0/0 description "BR6-USERS"
set interfaces ge-0/0/1 unit 0 family inet address 172.20.6.1/30
set interfaces ge-0/0/1 description "WAN-TO-HUB"
set routing-options static route 0.0.0.0/0 next-hop 172.20.6.2
"""},
    "panos": {"label": "Palo Alto PAN-OS (set)", "ext": ".set", "example": """set deviceconfig system hostname DMZ-FW2
set network interface ethernet ethernet1/1 layer3 ip 10.200.0.2/24
set network interface ethernet ethernet1/2 layer3 ip 10.210.0.1/24
set zone outside network layer3 ethernet1/1
set zone web network layer3 ethernet1/2
set network virtual-router default routing-table ip static-route default-out destination 0.0.0.0/0
set network virtual-router default routing-table ip static-route default-out nexthop ip-address 10.200.0.1
set address web-servers ip-netmask 10.210.0.0/24
set service svc-https protocol tcp port 443
set rulebase security rules allow-web from outside
set rulebase security rules allow-web to web
set rulebase security rules allow-web source any
set rulebase security rules allow-web destination web-servers
set rulebase security rules allow-web service svc-https
set rulebase security rules allow-web action allow
"""},
    "fortios": {"label": "Fortinet FortiOS", "ext": ".conf", "example": """config system global
    set hostname "BR7"
end
config system interface
    edit "wan1"
        set ip 172.20.7.1 255.255.255.252
    next
    edit "lan"
        set ip 10.17.0.1 255.255.255.0
    next
end
config router static
    edit 1
        set dst 0.0.0.0 0.0.0.0
        set gateway 172.20.7.2
        set device "wan1"
    next
end
config firewall address
    edit "br7-lan"
        set subnet 10.17.0.0 255.255.255.0
    next
end
config firewall policy
    edit 1
        set name "lan-to-wan"
        set srcintf "lan"
        set dstintf "wan1"
        set srcaddr "br7-lan"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
    next
end
"""},
}
assert set(VENDORS) == set(DRIVERS)


class ChangeError(ValueError):
    """A change that was refused; the message is shown to the user."""


# ---- inventory file -------------------------------------------------------

def read_inventory(snap: Path) -> dict:
    return json.loads((snap / "inventory.json").read_text())


def write_inventory(snap: Path, inv: dict) -> None:
    (snap / "inventory.json").write_text(json.dumps(inv, indent=2) + "\n")


def entry_for(inv: dict, network: Network, name: str) -> dict:
    dev = network.devices.get(name)
    if dev is None:
        raise ChangeError(f"no device {name!r}")
    return next(e for e in inv["devices"] if e["file"] == dev.vendor_extra["source_file"])


# ---- parse + impact (no writes) ---------------------------------------------

def parse_config(vendor: str, config: str) -> Device:
    if vendor not in VENDORS:
        raise ChangeError(f"unknown vendor {vendor!r}")
    if not config.strip():
        raise ChangeError("config is empty")
    try:
        dev = get_driver(vendor).parse(config)
    except ValidationError as e:
        msgs = "; ".join(err["msg"].removeprefix("Value error, ") for err in e.errors())
        raise ChangeError(f"config parsed but is inconsistent: {msgs}") from None
    except Exception as e:  # driver bugs and bad input both surface as a readable refusal
        raise ChangeError(f"could not parse {VENDORS[vendor]['label']} config: {e}") from None
    if dev.name == "unknown":
        raise ChangeError(f"no hostname found for {VENDORS[vendor]['label']}; is the right vendor selected?")
    if not any(i.ip for i in dev.interfaces):
        raise ChangeError("no interface with an IPv4 address was found; check the vendor selection")
    return dev


def preview(snap: Path, network: Network, vendor: str, config: str, replacing: str | None = None) -> dict:
    """Parse a candidate config and report what adding it would change, without writing anything."""
    dev = parse_config(vendor, config)
    others = {n: d for n, d in network.devices.items() if n != replacing}
    if dev.name in others:
        raise ChangeError(f"a device named {dev.name!r} already exists in this snapshot")

    warnings = []
    owned = {i.ip.ip: (d.name, i.name) for d in others.values() for i in d.interfaces if i.enabled and i.ip}
    for i in dev.interfaces:
        if i.enabled and i.ip and i.ip.ip in owned:
            o = owned[i.ip.ip]
            warnings.append(f"duplicate IP {i.ip.ip}: also on {o[0]} {o[1]}")

    dev.vendor_extra["source_file"] = "(new)"
    after_net = Network(devices={**others, dev.name: dev})
    after_twin = Twin(after_net)
    warnings += [w.split(": ", 1)[1] for w in after_twin.warnings if w.startswith(f"{dev.name}:")]

    topo = build_topology(after_net)
    links = []
    for e in topo.edges:
        if dev.name not in (e["source"], e["target"]):
            continue
        mine, other, oif = (e["source_if"], e["target"], e["target_if"]) if e["source"] == dev.name else (e["target_if"], e["source"], e["source_if"])
        links.append({"interface": mine, "subnet": e["subnet"],
                      "to": "LAN" if other.startswith("net:") else other, "to_interface": oif})

    return {
        "name": dev.name, "vendor": dev.vendor, "role": dev.role,
        "interfaces": [{"name": i.name, "ip": str(i.ip) if i.ip else "", "zone": i.zone or "", "enabled": i.enabled} for i in dev.interfaces],
        "routes": [{"prefix": str(r.prefix), "next_hop": str(r.next_hop or r.interface), "admin_distance": r.admin_distance} for r in dev.routes],
        "policies": [{"name": p.name, "action": p.action, "enabled": p.enabled} for p in dev.policies],
        "links": links,
        "unsupported": dev.unsupported,
        "warnings": warnings,
        "impact": flow_impact(snap, Twin(network), after_twin),
    }


def flow_impact(snap: Path, before: Twin, after: Twin) -> list[dict]:
    """Saved flows whose result changes because of the edit."""
    flows_file = snap / "flows.json"
    if not flows_file.is_file():
        return []
    out = []
    for name, f, _ in load_flows(flows_file):
        b, a = before.analyze(f).kinds(), after.analyze(f).kinds()
        if a != b:
            out.append({"name": name, "flow": str(f), "before": b, "after": a})
    return out


# ---- writes -----------------------------------------------------------------

def _filename(snap: Path, name: str, vendor: str) -> str:
    stem = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-") or "device"
    ext = VENDORS[vendor]["ext"]
    fn, n = f"{stem}{ext}", 2
    while (snap / fn).exists():
        fn, n = f"{stem}-{n}{ext}", n + 1
    return fn


def add_device(snap: Path, network: Network, vendor: str, config: str, site: str = "") -> str:
    dev = parse_config(vendor, config)
    if dev.name in network.devices:
        raise ChangeError(f"a device named {dev.name!r} already exists in this snapshot")
    fn = _filename(snap, dev.name, vendor)
    with _Transaction(snap, fn):
        (snap / fn).write_text(config if config.endswith("\n") else config + "\n")
        inv = read_inventory(snap)
        entry = {"file": fn, "vendor": vendor}
        if site:
            entry["site"] = site
        inv["devices"].append(entry)
        write_inventory(snap, inv)
    return dev.name


def update_device(snap: Path, network: Network, name: str, config: str, site: str | None = None) -> str:
    inv = read_inventory(snap)
    entry = entry_for(inv, network, name)
    dev = parse_config(entry["vendor"], config)
    if dev.name != name and dev.name in network.devices:
        raise ChangeError(f"hostname changed to {dev.name!r}, which already exists")
    with _Transaction(snap, entry["file"]):
        (snap / entry["file"]).write_text(config if config.endswith("\n") else config + "\n")
        if site is not None:
            if site:
                entry["site"] = site
            else:
                entry.pop("site", None)
        write_inventory(snap, inv)
    return dev.name


def remove_device(snap: Path, network: Network, name: str) -> None:
    inv = read_inventory(snap)
    entry = entry_for(inv, network, name)
    inv["devices"].remove(entry)
    trash = snap / "_removed"
    trash.mkdir(exist_ok=True)
    shutil.move(snap / entry["file"], trash / entry["file"])
    write_inventory(snap, inv)


def save_layout(snap: Path, network: Network, positions: dict[str, list[float]]) -> None:
    inv = read_inventory(snap)
    for name, (x, y) in positions.items():
        entry_for(inv, network, name)["pos"] = [round(x), round(y)]
    write_inventory(snap, inv)


def create_snapshot(samples: Path, name: str, description: str = "", copy_from: str | None = None) -> None:
    if not SNAPSHOT_NAME.match(name):
        raise ChangeError("snapshot name: lowercase letters, digits, - and _ only (max 41 chars)")
    dest = samples / name
    if dest.exists():
        raise ChangeError(f"snapshot {name!r} already exists")
    if copy_from:
        src = samples / copy_from
        if not (src / "inventory.json").is_file():
            raise ChangeError(f"no snapshot {copy_from!r} to copy")
        shutil.copytree(src, dest, ignore=shutil.ignore_patterns("_removed"))
        inv = read_inventory(dest)
        inv["description"] = description or f"Copy of {copy_from}"
        write_inventory(dest, inv)
    else:
        dest.mkdir()
        write_inventory(dest, {"description": description, "devices": []})
        (dest / "flows.json").write_text("[]\n")


class _Transaction:
    """Remember file contents before a change and put them back if the snapshot no longer loads."""

    def __init__(self, snap: Path, *files: str):
        self.snap = snap
        self.saved = {f: (snap / f).read_text() if (snap / f).exists() else None for f in ("inventory.json", *files)}

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc_type is None:
            try:
                load_snapshot(self.snap)
                return False
            except Exception as e:
                self._restore()
                raise ChangeError(f"change rejected, snapshot would not load: {e}") from None
        self._restore()
        return False

    def _restore(self):
        for f, text in self.saved.items():
            if text is None:
                (self.snap / f).unlink(missing_ok=True)
            else:
                (self.snap / f).write_text(text)
