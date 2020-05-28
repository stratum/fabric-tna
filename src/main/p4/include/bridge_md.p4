
#ifndef __BRIDGE_MD__
#define __BRIDGE_MD__

#include "define.p4"
#include "header.p4"

action set_up_bridge_md(out bridge_metadata_t bridge_md,
                        in ingress_intrinsic_metadata_t ig_intr_md,
                        in fabric_ingress_metadata_t fabric_md) {
    bridge_md.setValid();
    bridge_md.vlan_id = fabric_md.vlan_id;
    bridge_md.vlan_pri = fabric_md.vlan_pri;
    bridge_md.vlan_cfi = fabric_md.vlan_cfi;
#ifdef WITH_DOUBLE_VLAN_TERMINATION
    bridge_md.push_double_vlan = fabric_md.push_double_vlan;
    bridge_md.inner_vlan_id = fabric_md.inner_vlan_id;
    bridge_md.inner_vlan_pri = fabric_md.inner_vlan_pri;
    bridge_md.inner_vlan_cfi = fabric_md.inner_vlan_cfi;
#endif // WITH_DOUBLE_VLAN_TERMINATION
    bridge_md.ip_eth_type = fabric_md.ip_eth_type;
    bridge_md.ip_proto = fabric_md.ip_proto;
    bridge_md.mpls_label = fabric_md.mpls_label;
    bridge_md.mpls_ttl = fabric_md.mpls_ttl;
    bridge_md.l4_sport = fabric_md.l4_sport;
    bridge_md.l4_dport = fabric_md.l4_dport;
    bridge_md.is_multicast = fabric_md.is_multicast;
    bridge_md.is_mirror = fabric_md.is_mirror;
    bridge_md.mirror_id = fabric_md.mirror_id;
    bridge_md.ingress_port = ig_intr_md.ingress_port;
}
#endif