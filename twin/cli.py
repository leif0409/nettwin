"""Command line: python -m twin <command> ...  (run with --help)."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from twin.engine import FlowReport, Twin
from twin.loader import load_flows, load_observed, load_snapshot
from twin.model import Flow
from twin.recommend import Recommendation, recommend

DEFAULT_SNAPSHOT = Path(__file__).resolve().parent.parent / "samples" / "lab1"


def format_report(rep: FlowReport, rec: Recommendation | None = None) -> str:
    out = [f"Flow: {rep.flow}", "", "Forward path(s):"]
    out += [f"  {p}" for p in rep.forward]
    out += ["Return path(s):"]
    out += [f"  {p}" for p in rep.reverse]
    if rep.checks:
        out += ["Firewall decisions (forward):"]
        for c in rep.checks:
            rule = c.decision.rule or "<default>"
            out.append(f"  {c.device} {c.in_zone}->{c.out_zone}: {c.decision.action.upper()} by {rule}")
    out += ["", "Result: OK" if rep.ok else "Issues:"]
    out += [f"  - {i.kind} at {i.device}: {i.message}" for i in rep.issues]
    if rec is not None and not rep.ok:
        out.append("")
        if rec.blockers:
            out.append("No rules proposed. Fix these first (not solvable by adding policy):")
            out += [f"  - {b}" for b in rec.blockers]
        for pr in rec.rules:
            out += [f"Proposed rule on {pr.device} ({pr.vendor}):", *[f"    {line}" for line in pr.rendered.splitlines()]]
        if rec.rules:
            out.append(f"Validation against twin after change: {'PASS' if rec.validated else 'FAIL ' + str(rec.after.kinds())}")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="twin", description="Network digital twin prototype (offline, sample configs).")
    ap.add_argument("--snapshot", default=str(DEFAULT_SNAPSHOT), help="directory with inventory.json and configs")
    sub = ap.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("check", help="analyze one flow and propose rules")
    c.add_argument("src")
    c.add_argument("dst")
    c.add_argument("protocol", choices=["tcp", "udp", "icmp"])
    c.add_argument("port", nargs="?", type=int)

    b = sub.add_parser("batch", help="analyze every flow in a JSON file")
    b.add_argument("flows", nargs="?", help="defaults to <snapshot>/flows.json")

    sub.add_parser("model", help="dump the neutral model as JSON")
    sub.add_parser("warnings", help="show parser and RIB warnings (unsupported features, uninstalled routes)")

    args = ap.parse_args(argv)
    net = load_snapshot(args.snapshot)
    twin = Twin(net)

    if args.cmd == "check":
        rep = twin.analyze(Flow(src=args.src, dst=args.dst, protocol=args.protocol, port=args.port))
        print(format_report(rep, recommend(twin, rep)))
        return 0 if rep.ok else 1

    if args.cmd == "batch":
        failures = 0
        flows_file = args.flows or Path(args.snapshot) / "flows.json"
        observed = load_observed(flows_file)
        for name, flow, expect in load_flows(flows_file):
            rep = twin.analyze(flow)
            got = rep.kinds()
            verdict = "" if expect is None else ("  expected" if got == sorted(expect) else f"  UNEXPECTED (wanted {sorted(expect)})")
            failures += verdict.startswith("  UNEXPECTED")
            if name in observed:
                predicted = "allowed" if rep.ok else "blocked"
                agrees = predicted == observed[name]
                failures += not agrees
                verdict += f"  | lab: {observed[name]} -> {'twin agrees' if agrees else 'TWIN DISAGREES'}"
            print(f"{name:22} {str(flow):42} {'OK' if rep.ok else ','.join(got)}{verdict}")
        return 1 if failures else 0

    if args.cmd == "model":
        print(json.dumps(net.model_dump(mode="json"), indent=2))
        return 0

    if args.cmd == "warnings":
        for dev in net.devices.values():
            for u in dev.unsupported:
                print(f"{dev.name}: not modeled: {u}")
        for w in twin.warnings:
            print(w)
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
