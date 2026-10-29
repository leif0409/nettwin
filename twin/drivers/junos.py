"""Juniper Junos router driver ("display set" subset: interfaces, static routes incl. ECMP)."""
from __future__ import annotations

from twin.drivers.base import Driver, tokens
from twin.model import Device, Interface, Route

STATIC_PREFERENCE = 5


class JunosDriver(Driver):
    vendor = "junos"
    role = "router"

    def parse(self, text: str) -> Device:
        hostname = "unknown"
        units: dict[str, dict] = {}
        disabled_phys: set[str] = set()
        descriptions: dict[str, str] = {}
        statics: dict[str, dict] = {}
        unsupported: list[str] = []

        for line in text.splitlines():
            line = line.strip()
            if not line.startswith("set "):
                continue
            t = tokens(line)[1:]

            if t[:2] == ["system", "host-name"]:
                hostname = t[2]
            elif t[0] == "interfaces":
                phys = t[1]
                if t[2] == "description":
                    descriptions[phys] = t[3]
                elif t[2] == "disable":
                    disabled_phys.add(phys)
                elif t[2] == "unit":
                    u = units.setdefault(f"{phys}.{t[3]}", {"phys": phys})
                    rest = t[4:]
                    if rest[:3] == ["family", "inet", "address"]:
                        if "ip" in u:
                            unsupported.append(f"{phys}.{t[3]}: additional address {rest[3]}")
                        else:
                            u["ip"] = rest[3]
                    elif rest[:1] == ["disable"]:
                        u["enabled"] = False
            elif t[:3] == ["routing-options", "static", "route"]:
                r = statics.setdefault(t[3], {"next_hops": [], "pref": STATIC_PREFERENCE})
                rest = t[4:]
                if rest[0] == "next-hop":
                    r["next_hops"].append(rest[1])
                elif rest[0] == "preference":
                    r["pref"] = int(rest[1])
                else:
                    unsupported.append(f"static route {t[3]} {' '.join(rest)}")
            elif t[0] in ("protocols", "routing-instances", "security", "firewall"):
                key = " ".join(t[:3])
                if key not in unsupported:
                    unsupported.append(key)

        interfaces = [
            Interface(
                name=name,
                ip=u.get("ip"),
                enabled=u.get("enabled", True) and u["phys"] not in disabled_phys,
                description=descriptions.get(u["phys"], ""),
                # out-of-band management ports
                vrf="management" if u["phys"] in ("fxp0", "em0", "me0") else "default",
            )
            for name, u in units.items()
        ]
        routes = [
            Route(prefix=prefix, next_hop=nh, admin_distance=r["pref"])
            for prefix, r in statics.items()
            for nh in r["next_hops"]  # several next-hops on one route = ECMP
        ]
        return Device(
            name=hostname, vendor=self.vendor, role="router",
            interfaces=interfaces, routes=routes, unsupported=unsupported,
        )
