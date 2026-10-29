Generate the synthetic "global-corp" lab: 35 devices across NA and EMEA in real vendor syntax.


    python tools/gen_global_lab.py samples/global-corp

SYNTHETIC: the configs follow real Cisco IOS-XE / NX-OS / Junos / PAN-OS / FortiOS syntax,
and each router/switch also gets a routing table in that platform's real output format
(IOS-XE `show ip route`, NX-OS `show ip route vrf all`, Junos `show route | display json`).
Those routing tables are computed here from the design (shortest paths, ECMP), and the
firewalls' static routes are derived from the same paths, so the lab is self-consistent.
NetTwin agreeing with it shows the parsers and analysis work at scale; it is not
independent ground truth (the real-* snapshots are).

Output is deterministic: running it twice gives byte-identical files.

Planted problems (each has a flow in flows.json):
- na-hq-core2 has a "temporary" static for the EMEA app subnet over a legacy backup circuit
  that bypasses na-hq-fw1. core2 is HSRP-active for the HQ users VLAN, so users' requests
  skip the HQ firewall while replies come back through it.
- eu-br-mad-rtr1's BGP export policy has a typo (10.35.20.0/24 instead of 10.35.2.0/24),
  so the Madrid LAN is never advertised: requests leave, replies follow the default to the internet.
- eu-dc1-fw1 explicitly denies NA -> EMEA customer DB (data residency), and has no rule for
  NA IT on tcp/8443 to the EMEA app tier.
- na-dc1-fw1 has a disabled "temp-vendor-access" rule; both internet firewalls have NAT
  (not modeled, flagged).
