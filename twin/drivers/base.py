"""Driver interface. One driver per vendor; each converts that vendor's config into the neutral model."""
from __future__ import annotations

import shlex
from abc import ABC, abstractmethod
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network, summarize_address_range
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from twin.model import Device


@dataclass
class RuleRequest:
    """A vendor-neutral firewall rule the recommender wants rendered in vendor syntax."""

    name: str
    src_zone: str
    dst_zone: str
    src: IPv4Network
    dst: IPv4Network
    protocol: str
    port: int | None
    description: str

    @property
    def src_obj(self) -> str:
        return f"auto-{self.src.network_address}_{self.src.prefixlen}"

    @property
    def dst_obj(self) -> str:
        return f"auto-{self.dst.network_address}_{self.dst.prefixlen}"

    @property
    def svc_obj(self) -> str:
        return f"auto-{self.protocol}-{self.port}" if self.port is not None else f"auto-{self.protocol}"


class Driver(ABC):
    vendor: str
    role: str

    def collect(self, host: str, credentials: dict) -> str:
        # Live collection (SSH/API) is deliberately out of scope for the prototype:
        # snapshots are saved config files. A real driver would return raw text here.
        raise NotImplementedError("prototype reads saved config files; live collection is not implemented")

    @abstractmethod
    def parse(self, text: str) -> Device:
        """Turn raw config text into a neutral Device."""

    def render_policy(self, rule: RuleRequest) -> str:
        raise NotImplementedError(f"{self.vendor} has no policy renderer")


def tokens(line: str) -> list[str]:
    return shlex.split(line, posix=True)


def bracket_values(toks: list[str]) -> list[str]:
    """`[ a b ]` -> [a, b];  `a` -> [a]. Used by set-style configs."""
    if toks and toks[0] == "[":
        return toks[1 : toks.index("]")]
    return toks[:1]


def range_to_prefixes(start: str, end: str) -> list[IPv4Network]:
    return list(summarize_address_range(IPv4Address(start), IPv4Address(end)))


def parse_ports(spec: str) -> list[tuple[int, int]]:
    """'443,8080-8090' or '443 8080-8090' -> [(443, 443), (8080, 8090)]."""
    out = []
    for part in spec.replace(",", " ").split():
        part = part.split(":")[0]  # FortiOS dst:src syntax; source ports are not modeled
        lo, _, hi = part.partition("-")
        out.append((int(lo), int(hi or lo)))
    return out
