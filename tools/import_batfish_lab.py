"""Convert a lab from github.com/batfish/lab-validation into a NetTwin snapshot.

    python tools/import_batfish_lab.py <lab_dir> <snapshot_dir> [--description TEXT]

What it takes from the lab:
- configs/<device>/...      device configs (vendor detected from content)
- show/<device>/...         recorded routing tables, attached as the device's RIB
- hosts/<host>.json         end hosts (their IPs are the traffic sources)
- show/<host>/client_*.txt  recorded TCP/UDP tests  -> flows with "observed": allowed|blocked
  show/<host>/ping_*.txt    recorded pings          -> icmp flows with "observed"

The observed result is what really happened on the lab devices, so NetTwin's
prediction can be scored against it on the Verification page.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
from pathlib import Path

ROUTE_FILES = re.compile(r"^(show_ip_route(_vrf_[\w-]+)?|get_router_info_routing-table_all|run_show_routing_route)\.txt$")
CLIENT = re.compile(r"^client_(?P<host>[\w-]+)_(?P<ip>[\d.]+)_(?P<proto>tcp|udp)_(?P<port>\d+)\.txt$")
PING = re.compile(r"^ping_-c_1_-S_(?P<src>[\d.]+)_(?P<dst>[\d.]+)\.txt$")


def sniff(text: str) -> str | None:
    t = text[:20000]
    if "config system global" in t or "config system interface" in t:
        return "fortios"
    if "set deviceconfig" in t or "set network interface" in t:
        return "panos"
    if "set system host-name" in t or "set interfaces " in t:
        return "junos"
    if re.search(r"^hostname \S+", t, re.M) and "\ninterface " in t:
        return "cisco_ios"
    return None


def observed(proto: str, text: str) -> str:
    if proto == "icmp":
        return "allowed" if re.search(r"\b[1-9]\d* received", text) else "blocked"
    # Allowed only if every packet sent came back. App-ID firewalls let the first few packets
    # through while identifying the application, then drop the rest: that is a block.
    sent = len(re.findall(r"^packet\d+:", text, re.M))
    echoed = len(re.findall(r"^\[ECHO:\]", text, re.M))
    if proto == "tcp" and "timed out" in text:
        return "blocked"
    return "allowed" if sent and echoed == sent else "blocked"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("lab", type=Path)
    ap.add_argument("out", type=Path)
    ap.add_argument("--description", default="")
    args = ap.parse_args()
    lab, out = args.lab, args.out
    out.mkdir(parents=True, exist_ok=True)

    devices, skipped = [], []
    for dev_dir in sorted(p for p in (lab / "configs").iterdir()):
        files = [dev_dir] if dev_dir.is_file() else sorted(f for f in dev_dir.rglob("*") if f.is_file())
        for cfg in files:
            vendor = sniff(cfg.read_text(errors="replace"))
            name = dev_dir.stem if dev_dir.is_file() else dev_dir.name
            if vendor is None:
                skipped.append(f"{name} ({cfg.name}: vendor/format not supported)")
                continue
            dst = out / "configs" / f"{name}.txt"
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(cfg, dst)
            entry = {"file": f"configs/{name}.txt", "vendor": vendor}
            show = lab / "show" / name
            routes = sorted(f for f in show.glob("*.txt") if ROUTE_FILES.match(f.name)) if show.is_dir() else []
            if routes:
                for r in routes:
                    (out / "state" / name).mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(r, out / "state" / name / r.name)
                entry["routes"] = [f"state/{name}/{r.name}" for r in routes]
            devices.append(entry)

    hosts = {}
    for h in sorted((lab / "hosts").glob("*.json")) if (lab / "hosts").is_dir() else []:
        data = json.loads(h.read_text())
        ip = next(iter(data["hostInterfaces"].values()))["prefix"].split("/")[0]
        hosts[data["hostname"]] = ip

    flows = []
    for host, src in hosts.items():
        hdir = lab / "show" / host
        if not hdir.is_dir():
            continue
        for f in sorted(hdir.glob("*.txt")):
            text = f.read_text(errors="replace")
            if m := CLIENT.match(f.name):
                flows.append({"name": f"{host}-to-{m['host']}-{m['proto']}{m['port']}", "src": src, "dst": m["ip"],
                              "protocol": m["proto"], "port": int(m["port"]), "observed": observed(m["proto"], text)})
            elif (m := PING.match(f.name)) and m["src"] != m["dst"]:
                flows.append({"name": f"{host}-ping-{m['dst']}", "src": m["src"], "dst": m["dst"],
                              "protocol": "icmp", "observed": observed("icmp", text)})

    readme = (lab / "README.MD").read_text(errors="replace") if (lab / "README.MD").is_file() else ""
    (out / "SOURCE.md").write_text(
        f"# Source\n\nImported from https://github.com/batfish/lab-validation/tree/main/snapshots/{lab.name}\n"
        f"(Apache License 2.0, Copyright the Batfish authors). Configs, routing tables and test\n"
        f"results are unmodified copies.\n\n## Original README\n\n{readme}\n")
    inventory = {"description": args.description or f"Real lab: batfish/lab-validation {lab.name}", "devices": devices}
    (out / "inventory.json").write_text(json.dumps(inventory, indent=2) + "\n")
    (out / "flows.json").write_text(json.dumps(flows, indent=2) + "\n")
    print(f"{lab.name}: {len(devices)} devices, {len(flows)} recorded flows -> {out}")
    for s in skipped:
        print("  skipped", s)


if __name__ == "__main__":
    main()
