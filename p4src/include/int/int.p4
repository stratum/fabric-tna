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

control IntEgress (
    inout parsed_headers_t hdr,
    inout fabric_egress_metadata_t fabric_md,
    in    egress_intrinsic_metadata_t eg_intr_md,
    in egress_intrinsic_metadata_from_parser_t eg_prsr_md) {

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
#ifdef WITH_INT_SINK
        int_report.apply(hdr, fabric_md, eg_intr_md);
#endif
        if (fabric_md.common.ingress_port != CPU_PORT &&
            eg_intr_md.egress_port != CPU_PORT &&
            (hdr.udp.isValid() || hdr.tcp.isValid())) {
#ifdef WITH_INT_SOURCE
            int_source.apply(hdr, fabric_md, eg_intr_md);
#endif // WITH_INT_SOURCE
            if(hdr.int_header.isValid()) {
#ifdef WITH_INT_TRANSIT
                int_transit.apply(hdr, fabric_md, eg_intr_md, eg_prsr_md);
#endif // WITH_INT_TRANSIT
#ifdef WITH_INT_SINK
                int_sink.apply(hdr, fabric_md, eg_intr_md);
#endif // WITH_INT_SINK
#ifdef WITH_SPGW
                // We will set this later in spgw egress pipeline.
                fabric_md.int_mirror_md.skip_gtpu_headers = 0;
#endif // WITH_SPGW
            }
        }
    }
}
#endif
