// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0

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
        ingress_port_vlan_counter.count();
    }

    action permit() {
        // Allow packet as is.
        ingress_port_vlan_counter.count();
    }

    action permit_with_internal_vlan(vlan_id_t vlan_id) {
        fabric_md.vlan_id = vlan_id;
        permit();
    }

    // FIXME: remove the use of ternary match on inner VLAN.
    // Use multi-table approach to remove ternary matching
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
        fabric_md.fwd_type = fwd_type;
        fwd_classifier_counter.count();
    }

    table fwd_classifier {
        key = {
            ig_intr_md.ingress_port        : exact @name("ig_port");
            hdr.ethernet.dst_addr          : ternary @name("eth_dst");
            hdr.eth_type.value             : ternary @name("eth_type");
            fabric_md.ip_eth_type : exact @name("ip_eth_type");
        }
        actions = {
            set_forwarding_type;
        }
        const default_action = set_forwarding_type(FWD_BRIDGING);
        counters = fwd_classifier_counter;
        size = FWD_CLASSIFIER_TABLE_SIZE;
    }

    apply {
        // Initialize lookup metadata. Packets without a VLAN header will be
        // treated as belonging to a default VLAN ID (see parser).
        if (hdr.vlan_tag.isValid()) {
            fabric_md.vlan_id = hdr.vlan_tag.vlan_id;
            fabric_md.vlan_pri = hdr.vlan_tag.pri;
            fabric_md.vlan_cfi = hdr.vlan_tag.cfi;
        }
        #ifdef WITH_DOUBLE_VLAN_TERMINATION
        if (hdr.inner_vlan_tag.isValid()) {
            fabric_md.inner_vlan_id = hdr.inner_vlan_tag.vlan_id;
            fabric_md.inner_vlan_pri = hdr.inner_vlan_tag.pri;
            fabric_md.inner_vlan_cfi = hdr.inner_vlan_tag.cfi;
        }
        #endif // WITH_DOUBLE_VLAN_TERMINATION
        if (!hdr.mpls.isValid()) {
            // Packets with a valid MPLS header will have
            // fabric_md.mpls_ttl set to the packet's MPLS ttl value (see
            // parser). In any case, if we are forwarding via MPLS, ttl will be
            // decremented in egress.
            fabric_md.mpls_ttl = DEFAULT_MPLS_TTL + 1;
        }

        ingress_port_vlan.apply();
        fwd_classifier.apply();
    }
}
