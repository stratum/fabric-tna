// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

#include <core.p4>
#include <tna.p4>

#include "../header.p4"

control LoopbackTestingIngress(inout parsed_headers_t hdr,
                               inout fabric_ingress_metadata_t fabric_md,
                               inout ingress_intrinsic_metadata_for_tm_t ig_intr_md_for_tm,
                               inout ingress_intrinsic_metadata_for_deparser_t ig_intr_md_for_dprsr) {

    action on() {
        ig_intr_md_for_tm.copy_to_cpu = 1;
        ig_intr_md_for_dprsr.drop_ctl = 1;
        exit;
    }

    action off() {
        ig_intr_md_for_dprsr.drop_ctl = 1;
        exit;
    }

    table punt_to_cpu {
        key = { }
        actions = { on; off; }
        default_action = off;
    }

    apply {
        if (fabric_md.is_loopback) {
            punt_to_cpu.apply();
        }
    }
}

control LoopbackTestingEgress(inout parsed_headers_t hdr,
                              inout fabric_egress_metadata_t fabric_md,
                              in egress_intrinsic_metadata_t eg_intr_md) {

    action on() {
        hdr.fake_ethernet.setValid();
        hdr.fake_ethernet.ether_type = ETHERTYPE_LOOPBACK;
    }

    action off() { /* nop */ }

    table enable {
        key = { }
        actions = { on; off; }
        default_action = off;
    }

    apply { enable.apply(); }
}
