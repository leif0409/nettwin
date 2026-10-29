# Source

Imported from https://github.com/batfish/lab-validation/tree/main/snapshots/fortios_first_basic
(Apache License 2.0, Copyright the Batfish authors). Configs, routing tables and test
results are unmodified copies.

## Original README

## Topology

![Topology](Topology.png)

## LAB Facts

- First `fortios` basic lab
  - static routes only
  - two zones: inside(iosxe) & outside(iosxe)
  - `inside` & `outside` has default route pointing to `fw`
  - `fw` reaches to `insde(192.168.123.1) & outside(192.168.123.3)` via static routes
- 3 devices
  - d1_inside
    - iosxe
  - d2_fw
    - fortios
  - d3_outside
    - iosxe

