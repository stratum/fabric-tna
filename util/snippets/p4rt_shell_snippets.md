<!--
Copyright 2021-present Open Networking Foundation
SPDX-License-Identifier: Apache-2.0
-->
# P4RT-Shell Snippets

This document contains small snippets of code to be used in the
[P4Runtime-shell](https://github.com/p4lang/p4runtime-shell). They are designed
to be directly paste-able into the interactive shell.

## Starting a shell

After building the P4 program, use the following command to start Stratum, Tofino Model, and a P4Runtime shell.

See [README.md](README.md) for more information about how to build the pipeline.

```bash
./ptf/run/tm/p4rt-shell <profile>
```

## Snippets

### Set SwitchInfo for packetio

The pipeline needs to know switch model specific information to function
correctly.

```python
te = table_entry['switch_info'](action='set_switch_info')
te.action['cpu_port'] = '0xFFFFFFFD'
te.is_default = True
te.modify()
```

### Copy to CPU with ACL

Copy packets to CPU (and consequently the controller) by matching flows in the
ACL table. Also shows how to write and read flow counters.

```python
te = table_entry['FabricIngress.acl.acl'](action='FabricIngress.acl.copy_to_cpu')
te.match['ig_port'] = '260'
te.priority = 10
te.counter_data.byte_count = 1000
te.counter_data.packet_count = 50
te.insert()
te.read(lambda e: print(e))
```

### Create a clone session

```python
c = clone_session_entry(session_id=1)
c.cos = 7
c.replicas = [Replica(32, 0)]
c.insert()
clone_session_entry(session_id=0).read(lambda e: print(e))
```

### Create a multicast group

```python
m = multicast_group_entry(group_id=10)
m.add(1, 1).add(2, 1).add(3, 1)  # (port, replica)
m.insert()
multicast_group_entry(group_id=10).read(lambda e: print(e))
```

### Update an indirect counter

```python
ce = counter_entry["FabricIngress.spgw.pdr_counter"]
ce.index = 1
ce.byte_count = 100
ce.packet_count = 2
ce.modify()
ce.read(lambda e: print(e))
```

### Read a direct counter

```python
te = table_entry["FabricIngress.acl.acl"](action="FabricIngress.acl.drop")
te.match['eth_type'] = "0x800"
te.priority = 10
te.counter_data.byte_count = 100
te.counter_data.packet_count = 2
te.insert()
te.read(lambda e: print(e))
te.clear_action()
dc = direct_counter_entry["FabricIngress.acl.acl_counter"]
dc.table_entry = te
dc.read(lambda e: print(e))
```

### Use indirect actions with action profiles

```python
am = action_profile_member["FabricIngress.next.hashed_profile"]
am.member_id = 1
am.action = Action("FabricIngress.next.output_hashed")
am.action["port_num"] = "1"
am.insert()
am.read(lambda e: print(e))
ag = action_profile_group["FabricIngress.next.hashed_profile"](group_id=2)
ag.add(1)
ag.max_size = 16
ag.insert()
te = table_entry["FabricIngress.next.hashed"](action_profile_member=1)
te.match["next_id"] = "1"
te.member_id = 1
te.insert()
te.read(lambda e: print(e))
te = table_entry["FabricIngress.next.hashed"](action_profile_group=2)
te.match["next_id"] = "2"
te.group_id = 2
te.insert()
te.read(lambda e: print(e))
te_all = table_entry["FabricIngress.next.hashed"]
te_all.read(lambda e: print(e))
```

### Meters

```python
# Set meter with index 1
me = meter_entry["FabricIngress.qos.slice_tc_meter"]
me.index = 1
me.cir = 1000000
me.cburst = 10000
me.pir = 1500000
me.pburst = 15000
me.modify()
me.read(lambda e: print(e))

# Reset meter to default config
me = meter_entry["FabricIngress.qos.slice_tc_meter"]
me.index = 1
me.clear_config()
me.modify()
me.read(lambda e: print(e))
```

### Read all entries from all tables

```python
all_te = table_entry['FabricIngress.acl.acl']
all_te.id = 0
all_te.counter_data
all_te.read(lambda e: print(e))
```

### Simple ACL forwarding

To forward packets bidirectionally between port `260` and `268`:

```python
# Configure ports as VLAN untagged by explicitly popping the default VLAN ID 4096 (0xFFE)
te = table_entry['FabricEgress.egress_next.egress_vlan'](action='FabricEgress.egress_next.pop_vlan')
te.match['vlan_id'] = '0xFFE'
te.match['eg_port'] = '260'
te.insert()
te = table_entry['FabricEgress.egress_next.egress_vlan'](action='FabricEgress.egress_next.pop_vlan')
te.match['vlan_id'] = '0xFFE'
te.match['eg_port'] = '268'
te.insert()

# Insert ACL entries for bidirectional forwarding
te = table_entry['FabricIngress.acl.acl'](action='FabricIngress.acl.set_output_port')
te.match['ig_port'] = '260'
te.priority = 10
te.action['port_num'] = '268'
te.counter_data
te.insert()
te.read(lambda e: print(e))
te = table_entry['FabricIngress.acl.acl'](action='FabricIngress.acl.set_output_port')
te.match['ig_port'] = '268'
te.priority = 10
te.action['port_num'] = '260'
te.counter_data
te.insert()
te.read(lambda e: print(e))
```

### Create and send/receive packets

To create a packet (e.g., UDP):

```python
from scapy.all import *
pkt = (
    Ether(src='00:00:00:00:00:01', dst='00:00:00:00:00:02') /
    IP(src='192.168.0.1', dst='192.168.0.2') /
    UDP()
)
```

To send a packet to an interface:

```python
sendp(pkt, iface='veth1')
```

Note that when the Tofino Model container starts, it will automatically create 33 veth
pairs ( `veth0`-`veth1`, `veth2`-`veth3`, ...`veth62`-`veth63`, and `veth250`-`veth251`)

The following table is the default mapping from Tofino DP_ID to veth

| DP_ID | veth   |
|:-----:|:------:|
| 0     | veth1  |
| 1     | veth3  |
| 2     | veth5  |
| ..... | .....  |
| 31    | veth63 |

You can also sniff packets from interfaces, for example, to print every packet
received on interface `veth3`:

```python
sn = AsyncSniffer(iface='veth3', prn=lambda p: ls(p))
sn.start()
# ...
# To stop the sniffer and show summary
sn.stop()
```

### Use a custom Tofino model port mapping file

A port mapping file containes mappings from a device port to a veth interface pair.
The content of port mapping file looks like:

```json
{
  "PortToVeth": [
    { "device_port": 260, "veth1": 4, "veth2": 5 }
  ]
}
```

This file tells the Tofino model to map device port 260 to `veth4` and `veth5`.
The `veth4` will be attached to the Tofino model, and user can use `veth5` to send and
receive packets.

To use a custom Tofino model port mapping file, use `TM_PORT_JSON` environment variable to
pass additional paramter to the Tofino model, for example:

```bash
TM_PORT_JSON=ports.json ./ptf/run/tm/p4rt-shell fabric
```
