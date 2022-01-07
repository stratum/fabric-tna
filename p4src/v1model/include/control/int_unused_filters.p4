// Copyright 2022-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

#ifndef __INT_FILTERS__
#define __INT_FILTERS__

#include "v1model/include/define_v1model.p4"
#include "v1model/include/header_v1model.p4"

/*
    This file contains the porting of FlowReportFilter and DropReportFilter.
    These controls are actually unused due to v1model having only 1 queue.
 */

// By default report every 2^30 ns (~1 second)
const bit<48> DEFAULT_TIMESTAMP_MASK = 0xffffc0000000;
// or for hop latency changes greater than 2^8 ns
const bit<32> DEFAULT_HOP_LATENCY_MASK = 0xffffff00;
const queue_report_quota_t DEFAULT_QUEUE_REPORT_QUOTA = 1024;

// bmv2 specific for hash function.
const bit<32> max = 0xFFFF;
const bit<32> base = 0;


control FlowReportFilter(
    inout egress_headers_t hdr,
    inout fabric_v1model_metadata_t fabric_v1model,
    inout standard_metadata_t standard_md
    ) {

    fabric_egress_metadata_t fabric_md = fabric_v1model.egress;
    bit<16> digest = 0;
    bit<16> stored_digest = 0;
    bit<1> flag = 0;

    // Bloom filter with 2 hash functions storing flow digests. The digest is
    // the hash of:
    // - flow state (ingress port, egress port, quantized hop latency);
    // - quantized timestamp (to generate periodic reports).
    // - 5-tuple hash (to detect collisions);
    // We use such filter to reduce the volume of reports that the collector has
    // to ingest. We generate a report only when we detect a change, that is,
    // when the digest of the packet is different than the one of the previous
    // packet of the same flow.
    @hidden
    register<bit<16>>(1 << FLOW_REPORT_FILTER_WIDTH) filter1;
    @hidden
    register<bit<16>>(1 << FLOW_REPORT_FILTER_WIDTH) filter2;



    apply {
        if (fabric_md.int_report_md.report_type == INT_REPORT_TYPE_FLOW) {
            hash(
                digest,
                HashAlgorithm.crc16,
                base,
                {
                    fabric_md.bridged.base.ig_port,
                    standard_md.egress_spec,
                    fabric_md.int_md.hop_latency,
                    fabric_md.bridged.base.inner_hash,
                    fabric_md.int_md.timestamp
                },
                max
            );
            // Meaning of the result:
            // 1 digest did NOT change
            // 0 change detected

            // filter1 get and set
            filter1.read(stored_digest, (bit<32>)fabric_md.bridged.base.inner_hash[31:16]);
            flag = digest == stored_digest ? 1w1 : 1w0;
            filter1.write((bit<32>)fabric_md.bridged.base.inner_hash[31:16], digest);
            // filter2 get and set
            filter2.read(stored_digest, (bit<32>)fabric_md.bridged.base.inner_hash[15:0]);
            flag = flag | (digest == stored_digest ? 1w1 : 1w0);
            filter2.write((bit<32>)fabric_md.bridged.base.inner_hash[15:0], digest);

            // Generate report only when ALL register actions detect a change.
            if (flag == 1) {
                fabric_v1model.int_mirror_type = (bit<3>)FabricMirrorType_t.INVALID;
            }
            fabric_v1model.egress = fabric_md;
        }
    }
}


control DropReportFilter(
    inout egress_headers_t hdr,
    inout fabric_egress_metadata_t fabric_md,
    inout standard_metadata_t standard_md
    ) {

    bit<16> digest = 0;
    bit<16> stored_digest = 0;
    bit<1> flag = 0;

    // Bloom filter with 2 hash functions storing flow digests. The digest is
    // the hash of:
    // - quantized timestamp (to generate periodic reports).
    // - 5-tuple hash (to detect collisions);
    // We use such filter to reduce the volume of reports that the collector has
    // to ingest.
    @hidden
    register<bit<16>>(1 << DROP_REPORT_FILTER_WIDTH) filter1;
    @hidden
    register<bit<16>>(1 << DROP_REPORT_FILTER_WIDTH) filter2;

    apply {
        // This control is applied to all pkts, but we filter only INT mirrors.
        if (fabric_md.int_report_md.isValid() &&
                fabric_md.int_report_md.report_type == INT_REPORT_TYPE_DROP) {
            hash(
                digest,
                HashAlgorithm.crc16,
                base,
                {
                    fabric_md.int_report_md.flow_hash,
                    fabric_md.int_md.timestamp
                },
                max
            );

            // Meaning of the result:
            // flag = 1 digest did NOT change
            // flag = 0 change detected

            // filter 1 get and set
            filter1.read(stored_digest, (bit<32>)fabric_md.bridged.base.inner_hash[31:16]);
            flag = digest == stored_digest ? 1w1 : 1w0;
            filter1.write((bit<32>)fabric_md.bridged.base.inner_hash[31:16], digest);
            // filter 2 get and set
            filter2.read(stored_digest, (bit<32>)fabric_md.bridged.base.inner_hash[15:0]);
            flag = flag | (digest == stored_digest ? 1w1 : 1w0);
            filter2.write((bit<32>)fabric_md.bridged.base.inner_hash[15:0], digest);

            // Drop the report if we already report it within a period of time.
            if (flag == 1) {
                mark_to_drop(standard_md);
                exit;
            }
        }
    }
}
#endif // __INT_FILTERS__