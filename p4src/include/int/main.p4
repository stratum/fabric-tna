// Copyright 2017-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0

/* -*- P4_16 -*- */
#ifndef __INT_MAIN__
#define __INT_MAIN__

#ifdef WITH_INT_SOURCE
#include "source.p4"
#endif // WITH_INT_SOURCE

#ifdef WITH_INT_TRANSIT
#include "transit.p4"
#endif // WITH_INT_TRANSIT

#ifdef WITH_INT_SINK
#include "sink.p4"
#include "report.p4"
#endif // WITH_INT_SINK

control IntIngress (
    inout parsed_headers_t hdr,
    inout fabric_ingress_metadata_t fabric_md,
    in    ingress_intrinsic_metadata_t ig_intr_md,
    inout ingress_intrinsic_metadata_for_tm_t ig_intr_md_for_tm) {

    action int_set_source () {
        fabric_md.int_device_type = IntDeviceType.SOURCE;
    }

    table tb_set_source {
        key = {
            ig_intr_md.ingress_port: exact @name("ig_port");
        }
        actions = {
            int_set_source;
            @defaultonly nop();
        }
        const default_action = nop();
        size = MAX_PORTS;
    }

#ifdef WITH_INT_SINK

    action int_set_sink () {
        fabric_md.int_device_type = IntDeviceType.SINK;
    }

    table tb_set_sink {
        key = {
            ig_intr_md_for_tm.ucast_egress_port: exact @name("eg_spec");
        }
        actions = {
            int_set_sink;
            @defaultonly nop();
        }
        const default_action = nop();
        size = MAX_PORTS;
    }
#endif // WITH_INT_SINK

    apply {
        fabric_md.int_device_type = IntDeviceType.UNKNOWN;
        tb_set_source.apply();

#ifdef WITH_INT_SINK
        tb_set_sink.apply();
        if(fabric_md.int_device_type == IntDeviceType.SINK) {
            fabric_md.mirror_id = REPORT_MIRROR_SESSION_ID;
        }
#endif // WITH_INT_SINK
    }
}

control IntEgress (
    inout parsed_headers_t hdr,
    inout fabric_egress_metadata_t fabric_md,
    in    egress_intrinsic_metadata_t eg_intr_md,
    inout egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {

#ifdef WITH_INT_SOURCE
    IntSource() int_source;
#endif  // WITH_INT_SOURCE

#ifdef WITH_INT_TRANSIT
    IntTransit() int_transit;
#endif  // WITH_INT_TRANSIT

#ifdef WITH_INT_SINK
    IntSink() int_sink;
    IntReport() int_report;
#endif  // WITH_INT_SINK

    apply {
        if (fabric_md.ingress_port != CPU_PORT &&
            eg_intr_md.egress_port != CPU_PORT &&
            (hdr.udp.isValid() || hdr.tcp.isValid())) {
#ifdef WITH_INT_SOURCE
            if (fabric_md.int_device_type == IntDeviceType.SOURCE) {
                int_source.apply(hdr, fabric_md, eg_intr_md, eg_dprsr_md);
            }
#endif // WITH_INT_SOURCE
            if(hdr.int_header.isValid()) {
#ifdef WITH_INT_TRANSIT
                int_transit.apply(hdr, fabric_md, eg_intr_md, eg_dprsr_md);
#endif // WITH_INT_TRANSIT
#ifdef WITH_INT_SINK
                if (fabric_md.is_mirror && fabric_md.mirror_id == REPORT_MIRROR_SESSION_ID) {
                    /* send int report */
                    int_report.apply(hdr, fabric_md, eg_intr_md, eg_dprsr_md);
                }
                if (fabric_md.int_device_type == IntDeviceType.SINK) {
                    // int sink
                    int_sink.apply(hdr, fabric_md);
                }
#endif // WITH_INT_SINK
            }
        }
    }
}
#endif
