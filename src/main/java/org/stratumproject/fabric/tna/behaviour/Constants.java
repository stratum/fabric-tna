// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

// Do not modify this file manually, use `make constants` to generate this file.

package org.stratumproject.fabric.tna.behaviour;

import com.google.common.collect.ImmutableMap;

import java.util.List;
import java.util.Map;

import static org.onosproject.segmentrouting.metadata.SRObjectiveMetadata.EDGE_PORT;
import static org.onosproject.segmentrouting.metadata.SRObjectiveMetadata.INFRA_PORT;
import static org.onosproject.segmentrouting.metadata.SRObjectiveMetadata.PAIR_PORT;

/**
 * Constant values.
 */
public final class Constants {

    public static final byte[] ONE = new byte[]{1};
    public static final byte[] ZERO = new byte[]{0};

    // Used with port_type metadata
    public static final long PORT_TYPE_MASK = 0x3;
    public static final byte PORT_TYPE_UNKNOWN = 0x0;
    public static final byte PORT_TYPE_EDGE = 0x1;
    public static final byte PORT_TYPE_INFRA = 0x2;
    public static final byte PORT_TYPE_INTERNAL = 0x3;

    // Forwarding types from P4 program (not exposed in P4Info).
    public static final byte FWD_MPLS = 1;
    public static final byte FWD_IPV4_ROUTING = 2;
    public static final byte FWD_IPV6_ROUTING = 4;

    public static final short ETH_TYPE_EXACT_MASK = (short) 0xFFFF;

    // Recirculation ports, ordered per hw pipe (from 0 to 3).
    public static final List<Integer> RECIRC_PORTS = List.of(0x44, 0xc4, 0x144, 0x1c4);

    public static final int DEFAULT_VLAN = 4094;
    public static final int DEFAULT_PW_TRANSPORT_VLAN = 4090;
    public static final int PKT_IN_MIRROR_SESSION_ID = 0x210;

    // Static Queue IDs (should match those in gen-stratum-qos-config.py)
    public static final int QUEUE_ID_BEST_EFFORT = 0;
    public static final int QUEUE_ID_SYSTEM = 1;
    public static final int QUEUE_ID_CONTROL = 2;
    public static final int QUEUE_ID_FIRST_REAL_TIME = 3; // This will always be 3
    // FIXME: ELASTIC_ID can change and it should be configurable at runtime (i.e., via netcfg?)
    public static final int QUEUE_ID_FIRST_ELASTIC = 6; // TODO: this can change

    // Traffic Classes
    public static final int TC_BEST_EFFORT = 0; // Also the default TC
    public static final int TC_CONTROL = 1;
    public static final int TC_REAL_TIME = 2;
    public static final int TC_ELASTIC = 3;

    public static final int DEFAULT_SLICE_ID = 0;

    // Tofino Meter Colors
    // see: https://github.com/barefootnetworks/Open-Tofino/blob/master/share/p4c/p4include/tofino.p4
    public static final int COLOR_GREEN = 0;
    public static final int COLOR_YELLOW = 1;
    public static final int COLOR_RED = 3;

    // Bitwidths (not present in P4InfoConstants)
    public static final int SLICE_ID_BITWIDTH = 4;
    public static final int TC_BITWIDTH = 2;
    public static final int MAX_SLICE_ID = (1 << SLICE_ID_BITWIDTH) - 1;
    public static final int MAX_TC = (1 << TC_BITWIDTH) - 1;

    // Metadata to port type mapping
    public static final Map<Long, Byte> METADATA_TO_PORT_TYPE = ImmutableMap.<Long, Byte>builder()
            .put(PAIR_PORT, PORT_TYPE_INFRA)
            .put(EDGE_PORT, PORT_TYPE_EDGE)
            .put(INFRA_PORT, PORT_TYPE_INFRA)
            .build();

    // hide default constructor
    private Constants() {
    }
}
