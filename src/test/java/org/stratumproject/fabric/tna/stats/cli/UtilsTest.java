// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0
package org.stratumproject.fabric.tna.stats.cli;

import junit.framework.TestCase;
import org.onlab.packet.IpPrefix;
import org.onlab.packet.TpPort;
import org.onosproject.cli.net.IpProtocol;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.TrafficSelector;

public class UtilsTest extends TestCase {
    private static final String SRC_IP = "192.168.1.0/24";
    private static final String DST_IP = "192.168.2.0/24";
    private static final String PROTO_TCP = "TCP";
    private static final String PROTO_UDP = "UDP";
    private static final short SRC_PORT = 1234;
    private static final short DST_PORT = 5678;

    public void testBuildTrafficSelector() {
        TrafficSelector expect1 = DefaultTrafficSelector.builder()
                .matchIPSrc(IpPrefix.valueOf(SRC_IP))
                .matchIPDst(IpPrefix.valueOf(DST_IP))
                .matchIPProtocol((byte) (0xFF & IpProtocol.parseFromString(PROTO_TCP)))
                .matchTcpSrc(TpPort.tpPort(SRC_PORT))
                .matchTcpDst(TpPort.tpPort(DST_PORT))
                .build();
        TrafficSelector actual1 = Utils.buildTrafficSelector(SRC_IP, DST_IP, PROTO_TCP, SRC_PORT, DST_PORT);
        assertEquals(expect1, actual1);

        TrafficSelector expect2 = DefaultTrafficSelector.builder()
                .matchIPSrc(IpPrefix.valueOf(SRC_IP))
                .matchIPDst(IpPrefix.valueOf(DST_IP))
                .matchIPProtocol((byte) (0xFF & IpProtocol.parseFromString(PROTO_UDP)))
                .matchUdpSrc(TpPort.tpPort(SRC_PORT))
                .matchUdpDst(TpPort.tpPort(DST_PORT))
                .build();
        TrafficSelector actual2 = Utils.buildTrafficSelector(SRC_IP, DST_IP, PROTO_UDP, SRC_PORT, DST_PORT);
        assertEquals(expect2, actual2);

        TrafficSelector expect3 = DefaultTrafficSelector.builder()
                .matchIPSrc(IpPrefix.valueOf(SRC_IP))
                .matchIPDst(IpPrefix.valueOf(DST_IP))
                .build();
        TrafficSelector actual3 = Utils.buildTrafficSelector(SRC_IP, DST_IP, null, (short) 0, (short) 0);
        assertEquals(expect3, actual3);
    }
}
