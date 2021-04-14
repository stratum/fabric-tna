// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

#include <core.p4>
#include <tna.p4>

#include "../header.p4"

control Filtering (inout parsed_headers_t hdr,
                   inout fabric_ingress_metadata_t fabric_md,
                   in ingress_intrinsic_metadata_t ig_intr_md) {

    /*
     * Ingress Port VLAN Table.
     *
     * Filter packets based on ingress port and VLAN tag.
     */
    DirectCounter<bit<64>>(CounterType_t.PACKETS_AND_BYTES) ingress_port_vlan_counter;

    action deny() {
        // Packet from unconfigured port. Skip forwarding and next block.
        // Do ACL table in case we want to punt to cpu.
        fabric_md.skip_forwarding = true;
        fabric_md.skip_next = true;
        fabric_md.ig_port_type = PortType_t.UNKNOWN;
#ifdef WITH_INT
        fabric_md.int_mirror_md.drop_reason = IntDropReason_t.DROP_REASON_PORT_VLAN_MAPPING_MISS;
#endif // WITH_INT
        ingress_port_vlan_counter.count();
    }

    action permit(PortType_t port_type) {
        // Allow packet as is.
        fabric_md.ig_port_type = port_type;
        ingress_port_vlan_counter.count();
    }

    action permit_with_internal_vlan(vlan_id_t vlan_id, PortType_t port_type) {
        fabric_md.bridged.base.vlan_id = vlan_id;
        permit(port_type);
    }

    table ingress_port_vlan {
        key = {
            ig_intr_md.ingress_port    : exact @name("ig_port");
            hdr.vlan_tag.isValid()     : exact @name("vlan_is_valid");
            hdr.vlan_tag.vlan_id       : ternary @name("vlan_id");
#ifdef WITH_DOUBLE_VLAN_TERMINATION
            hdr.inner_vlan_tag.vlan_id : ternary @name("inner_vlan_id");
#endif // WITH_DOUBLE_VLAN_TERMINATION
        }
        actions = {
            deny();
            permit();
            permit_with_internal_vlan();
        }
        const default_action = deny();
        counters = ingress_port_vlan_counter;
        size = PORT_VLAN_TABLE_SIZE;
    }

    /*
     * Forwarding Classifier.
     *
     * Set which type of forwarding behavior to execute in the next control block.
     * There are six types of tables in Forwarding control block:
     * - Bridging: default forwarding type
     * - MPLS: destination mac address is the router mac and ethernet type is
     *   MPLS(0x8847)
     * - IP Multicast: destination mac address is multicast address and ethernet
     *   type is IP(0x0800 or 0x86dd)
     * - IP Unicast: destination mac address is router mac and ethernet type is
     *   IP(0x0800 or 0x86dd)
     */
    DirectCounter<bit<64>>(CounterType_t.PACKETS_AND_BYTES) fwd_classifier_counter;

    action set_forwarding_type(fwd_type_t fwd_type) {
        fabric_md.bridged.base.fwd_type = fwd_type;
        fwd_classifier_counter.count();
    }

#ifdef WTIH_DEBUG
    // FIXME: can this be removed? It was added to test indirect counters.
    Counter<bit<64>, bit<3>>(8, CounterType_t.PACKETS_AND_BYTES) fwd_type_counter;
#endif

    table fwd_classifier {
        key = {
            ig_intr_md.ingress_port                 : exact @name("ig_port");
            fabric_md.bridged.base.lkp_md.eth_dst                   : ternary @name("eth_dst");
            fabric_md.bridged.base.lkp_md.eth_type                      : ternary @name("eth_type");
            fabric_md.bridged.base.ip_eth_type      : exact @name("ip_eth_type");
        }
        actions = {
            set_forwarding_type;
        }
        const default_action = set_forwarding_type(FWD_BRIDGING);
        counters = fwd_classifier_counter;
        size = FWD_CLASSIFIER_TABLE_SIZE;
    }

    apply {
        ingress_port_vlan.apply();

        fabric_md.bridged.base.lkp_md.eth_dst = 0;
        if (hdr.ethernet.isValid()) {
            fabric_md.bridged.base.lkp_md.eth_dst = hdr.ethernet.dst_addr;
        }
        fabric_md.bridged.base.lkp_md.eth_type = 0;
        if (hdr.eth_type.isValid()) {
            fabric_md.bridged.base.lkp_md.eth_type = hdr.eth_type.value;
        }

        fwd_classifier.apply();
#ifdef WTIH_DEBUG
        fwd_type_counter.count(fabric_md.bridged.base.fwd_type);
#endif // WTIH_DEBUG
    }
}
