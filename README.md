# NetTwin: network digital twin prototype

An offline prototype of a network digital twin. It reads saved device configs
from four vendors, builds one vendor-neutral model, and answers the questions
the firewall-rule automation tool needs:

- Which path does this flow take, and which firewalls are on it? (ECMP included)
- Does each firewall allow it, and by which rule?
- Does the reply come back through the same firewalls? (catches asymmetric routing)
- If a rule is missing, what exact rule should be added, in that vendor's syntax?
  Does the flow pass once that rule is added to a copy of the model?

No devices or labs are needed. Everything runs on the sample configs in `samples/`.

## Run it

```bash
python -m venv .venv
```
```bash
.venv\Scripts\python.exe -m pip install -r requirements.txt
```
```bash
.venv\Scripts\python.exe -m uvicorn twin.web:app --port 8000
```

Open http://localhost:8000.

| Page | What it does |
|---|---|
| Network Map | Topology computed from configs. Click a device for details, or a subnet to use it in a path search. |
| Path Search | Source, destination, protocol and port. Shows forward and return paths on the map, each hop with its interfaces and zones, the matched firewall rule, findings, and a proposed vendor-specific rule that has been validated in the twin. |
| Inventory | Each device's interfaces and neighbors, routing table (marks routes that aren't installed), security rules in evaluation order, objects, features it doesn't model, and the raw config. |
| Verification | Re-runs every saved flow against the snapshot and compares the results with a baseline. Also lists network-wide findings. |
| Search | Look up an IP (owning interface, subnet, matching objects, each device's route lookup) or a name. |

The CLI covers the same engine:

```bash
.venv\Scripts\python.exe -m twin --snapshot samples/enterprise batch
```
```bash
.venv\Scripts\python.exe -m twin check 10.1.10.50 10.3.30.10 tcp 5432
```

Tests (drivers, engine, recommender, API, and both saved-flow baselines):

```bash
.venv\Scripts\python.exe -m pytest -q
```

## Sample snapshots

- **enterprise** (11 devices): 4 branches, a WAN hub, two DC core routers (ECMP), a DC firewall, an internet-edge firewall, an HQ firewall and an HQ core. Planted problems:
  - A typo'd route on WAN-HUB (`10.31.0.0/24` instead of `10.13.0.0/24`) breaks the return path to Branch 3.
  - A "temporary" route on HQ-CORE sends IT traffic around HQ-FW, so replies hit HQ-FW with no session.
  - Missing rules, explicit deny rules, a disabled rule, and NAT/BGP that the model flags as not modeled.
- **lab1** (4 devices): a minimal regression lab with its own planted bugs, including asymmetry, a routing loop and a blackhole.

### Real device data (`real-*` snapshots)

Imported from [batfish/lab-validation](https://github.com/batfish/lab-validation) (Apache-2.0). These are configs, routing tables and traffic tests captured from real device images. Each folder's `SOURCE.md` names the original lab.

| Snapshot | What it is | Checked against |
|---|---|---|
| `real-fortigate-policy` | FortiGate between inside and outside hosts, custom-service policies | 6 recorded traffic tests: **6/6 match** |
| `real-paloalto-appid` | Palo Alto with App-ID rules and application-override | 6 recorded traffic tests: **6/6 match**, including App-ID blocking UDP 9201 after its first packets |
| `real-fortigate-routed` | IOS-XE, FortiGate, IOS-XE, with imported routing tables | The devices' routing tables |
| `real-cisco-bgp-ospf` | 13 Cisco routers, 4 BGP ASes over OSPF, imported routing tables (ECMP, recursive BGP next hops) | The routers' own routing tables. Also flags a real duplicate loopback IP. |

On the Verification page, flows with an **observed** result show what really happened in the lab next to NetTwin's prediction.

**Routing tables (dynamic routing).** An inventory entry can list collected routing-table files:

```json
{"file": "configs/r1.txt", "vendor": "cisco_ios", "routes": ["state/r1/show_ip_route.txt"]}
```

These routes then replace the static routes from the config, so OSPF, BGP, EIGRP and redistribution results come directly from the device. Supported formats are Cisco `show ip route` (FortiOS `get router info routing-table all` uses the same layout) and PAN-OS `show routing route`. BGP next hops that aren't directly connected are resolved recursively. As on many platforms, the default route is never used to resolve a next hop.

**Importing more labs:**

```bash
.venv\Scripts\python.exe tools\import_batfish_lab.py <path-to-lab> samples\<new-snapshot>
```

## Adding and changing devices in the UI

- **+ Add device** (Inventory or Network Map): choose the vendor, then paste the config, upload the file, or click *Load example*. **Check config** parses it and shows what it would change before anything is saved:
  - which existing devices it links to (or a warning that it connects to nothing)
  - duplicate IPs, routes that can't be installed, and features the parser doesn't model
  - **impact on saved flows**: any flow whose result would change (for example "Return path broken → works")

  The save button stays disabled until the current text has passed the check.
- **Edit config** (device page): the same check-then-save flow for an existing device.
- **Remove** (device page): takes the device out of the snapshot. Its config file is moved to `<snapshot>/_removed/`, not deleted.
- **+ New** (next to the snapshot selector): create an empty snapshot, or copy an existing one so you can experiment without touching the original.
- **Drag devices** on the Network Map to arrange them. Positions are saved to `inventory.json`.

Every change is written to the snapshot folder (config file plus `inventory.json`). If the snapshot would no longer load after a change, the change is rolled back.

You can also add devices by hand: put the config file in a snapshot folder and add a line for it to that folder's `inventory.json` (file and vendor, plus optional site and map position).

## Layout

```
twin/model.py        vendor-neutral model (pydantic; bad driver output fails loudly)
twin/drivers/        one driver per vendor: cisco_ios, junos, panos, fortios
twin/engine.py       RIB build, longest-prefix match, ECMP, policy evaluation, asymmetry checks
twin/recommend.py    rule proposals, vendor rendering, validation on a model copy
twin/topology.py     L3 links and edge subnets derived from interfaces
twin/web.py          FastAPI JSON API + static UI
static/              single-page UI (Cytoscape.js for the map)
```

## Deliberate limits of the prototype

- Each driver parses a subset of its vendor's config. Anything it sees but doesn't model (NAT, BGP/OSPF, application-based rules, FQDN objects) is listed per device under "Not modeled" rather than silently ignored.
- Only static and connected routes are modeled. Dynamic routing would need RIB/FIB output from devices, not just configs.
- No NAT: address translation can change which rules match.
- Asymmetry is checked using the set of firewalls on all ECMP paths, not branch by branch.
- Rules are only proposed for a default deny, are added after the existing rules, and use /32 host objects. Explicit deny rules and routing problems are sent to a person.
- Live collection (`Driver.collect`) is a stub. It's the place to plug in SSH or API collection later.
