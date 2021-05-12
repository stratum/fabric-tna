<!--
Copyright 2021-present Open Networking Foundation
SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
-->

# Snippets to test deflect on drop INT report with P4Runtime shell

## To test deflect on drop feature on the software switch(Tofino Model)

```python

# Entries to forward any packet from port 0 to port 1
te = table_entry['FabricIngress.filtering.ingress_port_vlan'](action='permit_with_internal_vlan')
te.action['vlan_id'] = '100'
te.match['ig_port'] = '0'
te.match['vlan_is_valid'] = '0'
te.priority = 100
te.insert()
te = table_entry['acl'](action='set_output_port')
te.action['port_num'] = '1'
te.priority = 100
te.insert()

# Watch any flows
te = table_entry['FabricIngress.int_ingress.watchlist'](action='mark_to_report')
te.priority = 100
te.insert()

from scapy.all import sendp, Ether, IP, UDP
pkt = Ether() / IP() / UDP() / "AAAA"

for i in range(0, 9):
    sendp(pkt, iface="veth1")

# The 10th packet will be mark as deflected
sendp(pkt, iface="veth1")
```

## To test deflect on drop on a hardware switch

```python
# Allow IPv4 packets comes from port 1/0, 29/0, 30/0, 31/0, 32/0
for p in [260, 272, 280, 256, 264]:
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
    te.match['eth_dst'] = '00:90:fb:71:64:8a'
    te.match['ip_eth_type'] = '0x800'
    te.action['fwd_type'] = '2' # IPv4 routing type
    te.priority = 100
    te.insert()

# Allow recirculated packet with internal VLAN
te = table_entry['FabricIngress.filtering.ingress_port_vlan'](action='permit_with_internal_vlan')
te.action['vlan_id'] = '4094'
te.match['ig_port'] = '68'
te.match['vlan_is_valid'] = '0'
te.priority = 100
te.insert()

# Forwarding classifier for recirculated packets
te = table_entry['FabricIngress.filtering.fwd_classifier'](action='FabricIngress.filtering.set_forwarding_type')
te.match['ig_port'] = '68'
te.match['eth_dst'] = '00:90:fb:71:64:8a'
te.match['ip_eth_type'] = '0x800'
te.action['fwd_type'] = '2' # IPv4 routing type
te.priority = 100
te.insert()

# Watch any flows
te = table_entry['FabricIngress.int_pre_ingress.watchlist'](action='mark_to_report')
te.priority = 100
te.insert()

te = table_entry['FabricEgress.pkt_io_egress.switch_info'](action='set_switch_info')
te.action['cpu_port'] = '320'
te.is_default=True
te.modify()

# Inserts entries for default route
apm = action_profile_member['FabricIngress.next.hashed_profile'](action='FabricIngress.next.routing_hashed')
apm.member_id = 1
apm.action['port_num'] = '256'
apm.action['smac'] = '00:90:fb:71:64:8a'
apm.action['dmac'] = '00:00:00:00:00:03'
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
te.match['bmd_type'] = '4'  # DEFLECTED
te.match['mirror_type'] = '0'  # INVALID
te.match['int_report_type'] = '2'  # DROP
te.action['src_mac'] = '00:90:fb:71:64:8a'
te.action['mon_mac'] = '00:90:fb:71:64:8a'
te.action['src_ip'] = '10.128.13.29'
te.action['mon_ip'] = '192.168.4.1'
te.action['mon_port'] = '32766'
te.insert()

# Default forwarding behavior for report packet
te = table_entry['FabricIngress.acl.acl'](action='set_output_port')
te.match['ig_port'] = '68'
te.action['port_num'] = '260'
te.priority=1000
te.insert()

te = table_entry['FabricEgress.egress_next.egress_vlan'](action='FabricEgress.egress_next.pop_vlan')
te.match['vlan_id'] = '4094'
te.match['eg_port'] = '260'
te.insert()
```
