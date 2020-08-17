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
        ingress_port_vlan_counter.count();
    }

    action permit() {
        // Allow packet as is.
        ingress_port_vlan_counter.count();
    }

    action permit_with_internal_vlan(vlan_id_t vlan_id) {
        fabric_md.bridged.vlan_id = vlan_id;
        permit();
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
        fabric_md.fwd_type = fwd_type;
        fwd_classifier_counter.count();
    }

    /*
     * Counter that collects classes for all traffics.
     */
#ifdef WTIH_DEBUG
    Counter<bit<64>, bit<3>>(8, CounterType_t.PACKETS_AND_BYTES) fwd_type_counter;
#endif

    table fwd_classifier {
        key = {
            ig_intr_md.ingress_port        : exact @name("ig_port");
            hdr.ethernet.dst_addr          : ternary @name("eth_dst");
            hdr.eth_type.value             : ternary @name("eth_type");
            fabric_md.bridged.ip_eth_type  : exact @name("ip_eth_type");
        }
        actions = {
            set_forwarding_type;
        }
        const default_action = set_forwarding_type(FWD_BRIDGING);
        counters = fwd_classifier_counter;
        size = FWD_CLASSIFIER_TABLE_SIZE;
    }

#ifdef WITH_INT
    // FIXME: remove tables but use if on apply block on int report flag
    //  Since INT reports come in from the recirculation port, we need to bridge
    //  metadata to carry such int report flag. We could re-use a special eth-type
    //  as for packet-outs when that will be ready.

    @hidden
    action set_recirculate_pkt_vlan(vlan_id_t vlan_id) {
        fabric_md.bridged.vlan_id = vlan_id;
        // make the pipeline to handle it
        fabric_md.skip_forwarding = false;
        fabric_md.skip_next = false;
    }

    @hidden
    table recirc_ingress_port_vlan {
        key = {
            ig_intr_md.ingress_port    : exact @name("ig_port");
            hdr.vlan_tag.isValid()     : exact @name("vlan_is_valid");
        }
        actions = {
            set_recirculate_pkt_vlan;
        }
        size = 4;
        const entries = {
            (RECIRC_PORT_PIPE_0, false): set_recirculate_pkt_vlan(DEFAULT_VLAN_ID);
            (RECIRC_PORT_PIPE_1, false): set_recirculate_pkt_vlan(DEFAULT_VLAN_ID);
            (RECIRC_PORT_PIPE_2, false): set_recirculate_pkt_vlan(DEFAULT_VLAN_ID);
            (RECIRC_PORT_PIPE_3, false): set_recirculate_pkt_vlan(DEFAULT_VLAN_ID);
        }
    }

    @hidden
    action recirc_set_forwarding_type(fwd_type_t fwd_type) {
        fabric_md.fwd_type = fwd_type;
    }

    @hidden
    table recirc_fwd_classifier {
        key = {
            ig_intr_md.ingress_port        : exact @name("ig_port");
            fabric_md.bridged.ip_eth_type  : exact @name("ip_eth_type");
        }
        actions = {
            recirc_set_forwarding_type;
        }
        size = 4;
        const entries = {
            (RECIRC_PORT_PIPE_0, ETHERTYPE_IPV4): recirc_set_forwarding_type(FWD_IPV4_UNICAST);
            (RECIRC_PORT_PIPE_1, ETHERTYPE_IPV4): recirc_set_forwarding_type(FWD_IPV4_UNICAST);
            (RECIRC_PORT_PIPE_2, ETHERTYPE_IPV4): recirc_set_forwarding_type(FWD_IPV4_UNICAST);
            (RECIRC_PORT_PIPE_3, ETHERTYPE_IPV4): recirc_set_forwarding_type(FWD_IPV4_UNICAST);
        }
    }
#endif // WITH_INT

    apply {
        ingress_port_vlan.apply();
        fwd_classifier.apply();
#ifdef WITH_INT
        recirc_ingress_port_vlan.apply();
        recirc_fwd_classifier.apply();
#endif // WITH_INT
#ifdef WTIH_DEBUG
        fwd_type_counter.count(fabric_md.fwd_type);
#endif // WTIH_DEBUG
    }
}
