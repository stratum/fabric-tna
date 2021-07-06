<!--
Copyright 2021-present Open Networking Foundation
SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
-->

# Snippets to test deflect on drop INT report with P4Runtime shell

## To test deflect on drop on a hardware switch

Below is the P4Runtime shell snippets
After apply all codes to the P4runtime shell, send random IPv4 packet to the switch,
and you should be able to receive packets from port 256 (31/0) on the switch by default.

There are two ways to receive deflect on drop report:

- Disable port 256 (this is the easiest way to make the Tofino traffic manager to deflect
   the packet).
- Generate a huge amount of traffic to congest the port queue

When packet got deflected, you should be able to receive an INT drop report with drop reason 71
from port 264 (32/0).

```python
# Allow IPv4 packets comes from port 29/0, 31/0, 32/0
for p in [272, 256, 264]:
    te = table_entry['FabricIngress.filtering.ingress_port_vlan'](action='permit_with_internal_vlan')
    te.action['vlan_id'] = '100'
    te.match['ig_port'] = repr(p)
    te.match['vlan_is_valid'] = '0'
    te.priority = 100
    te.insert()
    te = table_entry['FabricEgress.egress_next.egress_vlan'](action='FabricEgress.egress_next.pop_vlan')
    te.match['vlan_id'] = '100'
    te.match['eg_port'] = repr(p)
    te.insert()
    te = table_entry['FabricIngress.filtering.fwd_classifier'](action='FabricIngress.filtering.set_forwarding_type')
    te.match['ig_port'] = repr(p)
    te.match['ip_eth_type'] = '0x800'
    te.action['fwd_type'] = '2' # IPv4 routing type
    te.priority = 100
    te.insert()

# Allow recirculated packet with internal VLAN
te = table_entry['FabricIngress.filtering.ingress_port_vlan'](action='permit_with_internal_vlan')
te.action['vlan_id'] = '4094'
te.match['ig_port'] = '0x144'
te.match['vlan_is_valid'] = '0'
te.priority = 100
te.insert()

# Forwarding classifier for recirculated packets
te = table_entry['FabricIngress.filtering.fwd_classifier'](action='FabricIngress.filtering.set_forwarding_type')
te.match['ig_port'] = '0x144'
te.match['ip_eth_type'] = '0x800'
te.action['fwd_type'] = '2' # IPv4 routing type
te.priority = 100
te.insert()

# Watch every flows
te = table_entry['FabricIngress.int_watchlist.watchlist'](action='mark_to_report')
te.priority = 100
te.insert()

# Inserts entries for default route, send to port 31/0
apm = action_profile_member['FabricIngress.next.hashed_profile'](action='FabricIngress.next.routing_hashed')
apm.member_id = 1
apm.action['port_num'] = '256' # 31/0
apm.action['smac'] = '00:aa:00:00:00:01'
apm.action['dmac'] = '00:bb:00:00:00:01'
apm.insert()

apg = action_profile_group['FabricIngress.next.hashed_profile']()
apg.group_id = 100
apg.add(1)
apg.max_size = 1
apg.insert()

te = table_entry['FabricIngress.next.hashed']()
te.group_id = 100
te.match['next_id'] = '100'
te.insert()

te = table_entry['FabricIngress.forwarding.routing_v4'](action='FabricIngress.forwarding.set_next_id_routing_v4')
te.action['next_id'] = '100'
te.is_default = True
te.modify()

# The INT report table
te = table_entry['FabricEgress.int_egress.report'](action='do_drop_report_encap')
te.match['bmd_type'] = '5'  # DEFLECTED
te.match['mirror_type'] = '0'  # INVALID
te.match['int_report_type'] = '2'  # DROP
te.action['src_mac'] = '00:cc:00:00:00:01'
te.action['mon_mac'] = '00:dd:00:00:00:01'
te.action['src_ip'] = '10.128.13.29'
te.action['mon_ip'] = '192.168.4.1'
te.action['mon_port'] = '32766'
te.insert()

# Default forwarding behavior for report packet
te = table_entry['FabricIngress.acl.acl'](action='set_output_port')
te.match['l4_dport'] = '32766' # INT report UDP port
te.action['port_num'] = '264' # 32/0
te.priority=1000
te.insert()

te = table_entry['FabricEgress.egress_next.egress_vlan'](action='FabricEgress.egress_next.pop_vlan')
te.match['vlan_id'] = '4094'
te.match['eg_port'] = '264' # 32/0
te.insert()
```
