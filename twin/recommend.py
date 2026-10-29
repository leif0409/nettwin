"""Turn a FlowReport into proposed firewall rules, rendered per vendor and validated against the twin.

Safety rules:
- Only a default-deny (no rule matched) is auto-fixed. An explicit deny rule is
  someone's decision and goes to a human.
- If the flow has routing or asymmetry problems, no rules are proposed: adding
  policy would not make the flow work, and the path may change once routing is fixed.
- Every proposal is applied to a copy of the model and the flow is re-analyzed.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from ipaddress import IPv4Network

from twin.drivers import RuleRequest, get_driver
from twin.engine import POLICY_DENY, FlowReport, Twin
from twin.model import AddressObject, Network, Policy, PortRange, Service, ServiceEntry


@dataclass
class ProposedRule:
    device: str
    vendor: str
    request: RuleRequest
    rendered: str


@dataclass
class Recommendation:
    rules: list[ProposedRule] = field(default_factory=list)
    blockers: list[str] = field(default_factory=list)
    after: FlowReport | None = None

    @property
    def validated(self) -> bool:
        return bool(self.rules) and self.after is not None and self.after.ok


def recommend(twin: Twin, report: FlowReport) -> Recommendation:
    rec = Recommendation()
    rec.blockers = [f"{i.kind}{f' at {i.device}' if i.device else ''}: {i.message}"
                    for i in report.issues if i.kind != POLICY_DENY]
    if rec.blockers or report.ok:
        return rec

    flow = report.flow
    tag = hashlib.sha1(str(flow).encode()).hexdigest()[:8]
    for check in report.checks:
        if check.decision.action != "deny":
            continue
        dev = twin.network.devices[check.device]
        req = RuleRequest(
            name=f"auto-{tag}",
            src_zone=check.in_zone,
            dst_zone=check.out_zone,
            src=IPv4Network(f"{flow.src}/32"),
            dst=IPv4Network(f"{flow.dst}/32"),
            protocol=flow.protocol,
            port=flow.port,
            description=f"auto: {flow}",
        )
        rec.rules.append(ProposedRule(dev.name, dev.vendor, req, get_driver(dev.vendor).render_policy(req)))

    rec.after = Twin(apply_rules(twin.network, rec.rules)).analyze(flow)
    return rec


def apply_rules(network: Network, rules: list[ProposedRule]) -> Network:
    """Return a copy of the network with the rules appended (after existing rules, before default deny)."""
    net = network.model_copy(deep=True)
    for pr in rules:
        r, dev = pr.request, net.devices[pr.device]
        dev.addresses[r.src_obj] = AddressObject(name=r.src_obj, prefixes=[r.src])
        dev.addresses[r.dst_obj] = AddressObject(name=r.dst_obj, prefixes=[r.dst])
        ports = [PortRange(start=r.port, end=r.port)] if r.port is not None else []
        dev.services[r.svc_obj] = Service(name=r.svc_obj, entries=[ServiceEntry(protocol=r.protocol, ports=ports)])
        dev.policies.append(Policy(
            name=r.name, src_zones=[r.src_zone], dst_zones=[r.dst_zone],
            src_addrs=[r.src_obj], dst_addrs=[r.dst_obj], services=[r.svc_obj],
            action="allow", description=r.description,
        ))
    return net
