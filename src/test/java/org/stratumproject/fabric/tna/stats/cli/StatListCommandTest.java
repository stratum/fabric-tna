// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.stats.cli;

import junit.framework.TestCase;
import org.easymock.EasyMock;
import org.onlab.packet.IpPrefix;
import org.onlab.packet.TpPort;
import org.onosproject.cli.net.IpProtocol;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.TrafficSelector;
import org.stratumproject.fabric.tna.stats.StatisticKey;
import org.stratumproject.fabric.tna.stats.StatisticService;

import java.util.Set;

public class StatListCommandTest extends TestCase {
    private static final int ID = 1;
    private static final String SRC_IP = "192.168.1.0/24";
    private static final String DST_IP = "192.168.2.0/24";
    private static final String PROTO_TCP = "TCP";
    private static final short SRC_PORT = 1234;
    private static final short DST_PORT = 5678;

    public void testDoExecute() {
        TrafficSelector selector = DefaultTrafficSelector.builder()
                .matchIPSrc(IpPrefix.valueOf(SRC_IP))
                .matchIPDst(IpPrefix.valueOf(DST_IP))
                .matchIPProtocol((byte) (0xFF & IpProtocol.parseFromString(PROTO_TCP)))
                .matchTcpSrc(TpPort.tpPort(SRC_PORT))
                .matchTcpDst(TpPort.tpPort(DST_PORT))
                .build();
        StatisticKey key = StatisticKey.builder()
                .withSelector(selector)
                .withId(ID)
                .build();

        StatisticService service = EasyMock.createMock(StatisticService.class);
        EasyMock.expect(service.getMonitors()).andReturn(Set.of(key)).once();
        EasyMock.replay(service);

        StatListCommand cmd = new StatListCommand() {
            @Override
            public <T> T getService(Class<T> serviceClass) {
                return (T) service;
            }
        };
        cmd.doExecute();

        EasyMock.verify(service);
    }
}