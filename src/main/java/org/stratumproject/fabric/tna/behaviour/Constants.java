// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

// Do not modify this file manually, use `make constants` to generate this file.

package org.stratumproject.fabric.tna.behaviour;

import java.util.List;

/**
 * Constant values.
 */
public final class Constants {

    public static final byte[] ONE = new byte[]{1};
    public static final byte[] ZERO = new byte[]{0};

    // Used with port_type metadata
    public static final long PORT_TYPE_MASK = 0x3;
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

    // UPF related constants
    public static final int UPF_INTERFACE_ACCESS = 1;
    public static final int UPF_INTERFACE_CORE = 2;
    public static final int UPF_INTERFACE_DBUF = 3;

    // hide default constructor
    private Constants() {
    }
}
