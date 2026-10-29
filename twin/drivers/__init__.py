from twin.drivers.base import Driver, RuleRequest
from twin.drivers.cisco_ios import CiscoIOSDriver
from twin.drivers.fortios import FortiOSDriver
from twin.drivers.junos import JunosDriver
from twin.drivers.panos import PanOSDriver

DRIVERS: dict[str, Driver] = {d.vendor: d for d in (CiscoIOSDriver(), JunosDriver(), PanOSDriver(), FortiOSDriver())}


def get_driver(vendor: str) -> Driver:
    try:
        return DRIVERS[vendor]
    except KeyError:
        raise ValueError(f"no driver for vendor {vendor!r}; known: {sorted(DRIVERS)}") from None


__all__ = ["DRIVERS", "Driver", "RuleRequest", "get_driver"]
