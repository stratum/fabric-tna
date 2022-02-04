// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0
package org.stratumproject.fabric.tna.stats.cli;

import org.onlab.packet.IPv4;
import org.onlab.packet.IpPrefix;
import org.onlab.packet.TpPort;
import org.onosproject.cli.net.IpProtocol;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.TrafficSelector;

/**
 * CLI command utilities.
 */
public final class Utils {

    private Utils() {
        // Private constructor
    }

    /**
     * Build TrafficSelector based on given parameters.
     *
     * @param srcIp source IP
     * @param dstIp destination IP
     * @param proto IP protocol
     * @param srcPort source port
     * @param dstPort destination port
     * @return TrafficSelector
     */
    public static TrafficSelector buildTrafficSelector(String srcIp, String dstIp, String proto,
                                                       short srcPort, short dstPort) {
        TrafficSelector.Builder builder = DefaultTrafficSelector.builder();

        if (srcIp != null) {
            builder.matchIPSrc(IpPrefix.valueOf(srcIp));
        }
        if (dstIp != null) {
            builder.matchIPDst(IpPrefix.valueOf(dstIp));
        }
        byte ipProtocol = 0;
        if (proto != null) {
            ipProtocol = (byte) (0xFF & IpProtocol.parseFromString(proto));
            builder.matchIPProtocol(ipProtocol);
        }
        if (srcPort != 0) {
            if (ipProtocol == IPv4.PROTOCOL_TCP) {
                builder.matchTcpSrc(TpPort.tpPort(srcPort));
            } else if (ipProtocol == IPv4.PROTOCOL_UDP) {
                builder.matchUdpSrc(TpPort.tpPort(srcPort));
            }
        }
        if (dstPort != 0) {
            if (ipProtocol == IPv4.PROTOCOL_TCP) {
                builder.matchTcpDst(TpPort.tpPort(dstPort));
            } else if (ipProtocol == IPv4.PROTOCOL_UDP) {
                builder.matchUdpDst(TpPort.tpPort(dstPort));
            }
        }

        return builder.build();
    }
}
