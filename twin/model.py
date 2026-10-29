"""Vendor-neutral network model.

Every vendor driver emits these objects and nothing else. The path engine,
policy evaluation and rule recommender only ever see this model, so adding a
vendor means writing one driver, not touching the engine.

Pydantic validation is deliberate: a driver that emits a route without a
target, or a policy that references an undefined object, fails loudly here
instead of producing wrong paths later.
"""
from __future__ import annotations

from ipaddress import IPv4Address, IPv4Interface, IPv4Network
from typing import Literal

from pydantic import BaseModel, Field, model_validator

ANY = "any"

Protocol = Literal["tcp", "udp", "icmp"]


class Interface(BaseModel):
    name: str
    ip: IPv4Interface | None = None
    zone: str | None = None
    vrf: str = "default"
    enabled: bool = True
    description: str = ""


class Route(BaseModel):
    prefix: IPv4Network
    next_hop: IPv4Address | None = None
    interface: str | None = None
    protocol: Literal["connected", "static", "ospf", "bgp", "eigrp", "rip", "isis", "other"] = "static"
    admin_distance: int
    vrf: str = "default"

    @model_validator(mode="after")
    def _has_target(self) -> Route:
        if self.next_hop is None and self.interface is None:
            raise ValueError(f"route {self.prefix} has neither next_hop nor interface")
        return self


class AddressObject(BaseModel):
    """A named address, already resolved to prefixes (groups and ranges flattened by the driver)."""

    name: str
    prefixes: list[IPv4Network]

    def contains(self, ip: IPv4Address) -> bool:
        return any(ip in p for p in self.prefixes)


class PortRange(BaseModel):
    start: int = Field(ge=0, le=65535)
    end: int = Field(ge=0, le=65535)

    @model_validator(mode="after")
    def _ordered(self) -> PortRange:
        if self.start > self.end:
            raise ValueError(f"port range {self.start}-{self.end} is reversed")
        return self


class ServiceEntry(BaseModel):
    protocol: Literal["tcp", "udp", "icmp", "any"]
    ports: list[PortRange] = Field(default_factory=list)  # empty = every port

    def matches(self, protocol: str, port: int | None) -> bool:
        if self.protocol != ANY and self.protocol != protocol:
            return False
        if not self.ports or port is None:
            return True
        return any(r.start <= port <= r.end for r in self.ports)


class Service(BaseModel):
    """A named service, already resolved (service groups flattened by the driver)."""

    name: str
    entries: list[ServiceEntry]

    def matches(self, protocol: str, port: int | None) -> bool:
        return any(e.matches(protocol, port) for e in self.entries)


class Policy(BaseModel):
    name: str
    src_zones: list[str] = Field(default_factory=lambda: [ANY])
    dst_zones: list[str] = Field(default_factory=lambda: [ANY])
    src_addrs: list[str] = Field(default_factory=lambda: [ANY])
    dst_addrs: list[str] = Field(default_factory=lambda: [ANY])
    services: list[str] = Field(default_factory=lambda: [ANY])
    action: Literal["allow", "deny"]
    enabled: bool = True
    description: str = ""


class Device(BaseModel):
    name: str
    vendor: str
    role: Literal["router", "firewall"]
    interfaces: list[Interface] = Field(default_factory=list)
    routes: list[Route] = Field(default_factory=list)  # connected routes are derived from interfaces
    # "config": routes are the static routes in the config. "state": routes come from the
    # device's collected routing table (show ip route ...), so dynamic protocols are included.
    rib_source: Literal["config", "state"] = "config"
    addresses: dict[str, AddressObject] = Field(default_factory=dict)
    services: dict[str, Service] = Field(default_factory=dict)
    policies: list[Policy] = Field(default_factory=list)  # in evaluation order
    default_action: Literal["allow", "deny"] = "deny"
    # Config features the driver saw but does not model. Surfaced in reports so
    # nobody mistakes "not modeled" for "not there".
    unsupported: list[str] = Field(default_factory=list)
    vendor_extra: dict = Field(default_factory=dict)

    @model_validator(mode="after")
    def _references_resolve(self) -> Device:
        names = {i.name for i in self.interfaces}
        for r in self.routes:
            if r.interface is not None and r.interface not in names:
                raise ValueError(f"{self.name}: route {r.prefix} uses unknown interface {r.interface}")
        for p in self.policies:
            for a in p.src_addrs + p.dst_addrs:
                if a != ANY and a not in self.addresses:
                    raise ValueError(f"{self.name}: policy {p.name} references unknown address {a!r}")
            for s in p.services:
                if s != ANY and s not in self.services:
                    raise ValueError(f"{self.name}: policy {p.name} references unknown service {s!r}")
        return self

    def interface(self, name: str) -> Interface | None:
        return next((i for i in self.interfaces if i.name == name), None)

    def connected_routes(self) -> list[Route]:
        return [
            Route(prefix=i.ip.network, interface=i.name, protocol="connected", admin_distance=0, vrf=i.vrf)
            for i in self.interfaces
            if i.enabled and i.ip is not None
        ]


class Network(BaseModel):
    devices: dict[str, Device]


class Flow(BaseModel):
    src: IPv4Address
    dst: IPv4Address
    protocol: Protocol
    port: int | None = Field(default=None, ge=0, le=65535)

    @model_validator(mode="after")
    def _port_for_l4(self) -> Flow:
        if self.protocol in ("tcp", "udp") and self.port is None:
            raise ValueError(f"{self.protocol} flow needs a destination port")
        return self

    def reversed(self) -> Flow:
        return Flow(src=self.dst, dst=self.src, protocol=self.protocol, port=self.port)

    def __str__(self) -> str:
        port = f"/{self.port}" if self.port is not None else ""
        return f"{self.src} -> {self.dst} {self.protocol}{port}"
