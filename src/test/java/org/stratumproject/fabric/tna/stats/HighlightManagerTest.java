// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0
package org.stratumproject.fabric.tna.stats;

import junit.framework.TestCase;
import org.easymock.EasyMock;
import org.junit.Before;
import org.onlab.packet.EthType;
import org.onlab.packet.IpAddress;
import org.onlab.packet.MacAddress;
import org.onlab.packet.VlanId;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.DefaultApplicationId;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DefaultHost;
import org.onosproject.net.DefaultLink;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Host;
import org.onosproject.net.HostId;
import org.onosproject.net.HostLocation;
import org.onosproject.net.Link;
import org.onosproject.net.PortNumber;
import org.onosproject.net.host.HostService;
import org.onosproject.net.link.LinkService;
import org.onosproject.net.provider.ProviderId;
import org.onosproject.store.service.DistributedSet;
import org.onosproject.ui.topo.Highlights;
import org.onosproject.ui.topo.Mod;

import java.util.List;
import java.util.Map;
import java.util.Set;

public class HighlightManagerTest extends TestCase {
    private static final ApplicationId APP_ID =
            new DefaultApplicationId(1, "HighlightManagerTest");

    private static final int ID = 1;
    private static final String NAME = "Traffic1";
    private static final String MOD = "style=\"stroke: #ff0000;\"";
    private static final HighlightKey H_KEY = HighlightKey.builder()
            .withId(ID)
            .withName(NAME)
            .withMod(new Mod(MOD))
            .build();

    // Link and host service
    private static final DeviceId DID_1 = DeviceId.deviceId("device1");
    private static final DeviceId DID_2 = DeviceId.deviceId("device2");
    private static final PortNumber PORT_INFRA = PortNumber.portNumber(1);
    private static final PortNumber PORT_EDGE = PortNumber.portNumber(2);
    private static final ConnectPoint CP_1 = new ConnectPoint(DID_1, PORT_INFRA);
    private static final ConnectPoint CP_2 = new ConnectPoint(DID_2, PORT_INFRA);
    private static final ConnectPoint CP_HOST = new ConnectPoint(DID_1, PORT_EDGE);
    private static final Link LINK = DefaultLink.builder()
            .providerId(ProviderId.NONE)
            .src(CP_1)
            .dst(CP_2)
            .type(Link.Type.DIRECT)
            .state(Link.State.ACTIVE)
            .build();
    private static final Host HOST = new DefaultHost(
            ProviderId.NONE,
            HostId.NONE,
            MacAddress.NONE,
            VlanId.NONE,
            Set.of(new HostLocation(CP_HOST, 0L)),
            null,
            Set.of(IpAddress.valueOf("192.168.1.1")),
            VlanId.NONE,
            EthType.EtherType.UNKNOWN.ethType(),
            false,
            false
    );

    // Statistic Map
    private static final long BYTE_1 = 500;
    private static final long BYTE_2 = 400;
    private static final long PACKET_1 = 100;
    private static final long PACKET_2 = 10;
    private static final long TIME_1 = 200;
    private static final long TIME_2 = 100;
    private static final StatisticDataKey S_KEY_1 = StatisticDataKey.builder()
            .withDeviceId(DID_1)
            .withPortNumber(PORT_INFRA)
            .withType(StatisticDataKey.Type.INGRESS)
            .build();
    private static final StatisticDataKey S_KEY_2 = StatisticDataKey.builder()
            .withDeviceId(DID_1)
            .withPortNumber(PORT_INFRA)
            .withType(StatisticDataKey.Type.EGRESS)
            .build();
    private static final StatisticDataKey S_KEY_3 = StatisticDataKey.builder()
            .withDeviceId(DID_2)
            .withPortNumber(PORT_INFRA)
            .withType(StatisticDataKey.Type.INGRESS)
            .build();
    private static final StatisticDataKey S_KEY_4 = StatisticDataKey.builder()
            .withDeviceId(DID_2)
            .withPortNumber(PORT_INFRA)
            .withType(StatisticDataKey.Type.EGRESS)
            .build();
    private static final StatisticDataValue S_VALUE_1 = StatisticDataValue.builder()
            .withByteCount(BYTE_1)
            .withPrevByteCount(BYTE_2)
            .withPacketCount(PACKET_1)
            .withPrevPacketCount(PACKET_2)
            .withTimeMs(TIME_1)
            .withPrevTimeMs(TIME_2)
            .build();
    private static final Map<StatisticDataKey, StatisticDataValue> S_MAP =
            Map.of(S_KEY_1, S_VALUE_1, S_KEY_2, S_VALUE_1, S_KEY_3, S_VALUE_1, S_KEY_4, S_VALUE_1);

    private final DistributedSet<HighlightKey> highlightStore = EasyMock.createMock(DistributedSet.class);
    private final LinkService linkService = EasyMock.createMock(LinkService.class);
    private final HostService hostService = EasyMock.createMock(HostService.class);
    private final StatisticService statisticService = EasyMock.createMock(StatisticService.class);
    private final HighlightManager mgr = new HighlightManager();

    @Before
    public void setUp() {
        mgr.appId = APP_ID;
        mgr.highlightStore = highlightStore;
        mgr.linkService = linkService;
        mgr.hostService = hostService;
        mgr.statisticService = statisticService;
    }

    public void testAddHighlight() {
        EasyMock.expect(highlightStore.add(H_KEY)).andReturn(true).once();
        EasyMock.replay(highlightStore);
        mgr.addHighlight(ID, NAME, new Mod(MOD));
        EasyMock.verify(highlightStore);
    }

    public void testRemoveHighlight() {
        EasyMock.expect(highlightStore.remove(H_KEY)).andReturn(true).once();
        EasyMock.replay(highlightStore);
        mgr.removeHighlight(ID, NAME, new Mod(MOD));
        EasyMock.verify(highlightStore);
    }

    public void testGetHighlights() {
        Set<HighlightKey> mockSet = Set.of(H_KEY);
        EasyMock.expect(highlightStore.size()).andReturn(mockSet.size()).once();
        EasyMock.expect(highlightStore.iterator()).andReturn(mockSet.iterator()).once();
        EasyMock.replay(highlightStore);
        Set<HighlightKey> keys = mgr.getHighlights();
        assertEquals(mockSet, keys);
        EasyMock.verify(highlightStore);
    }

    public void testHumanReadable() {
        assertEquals("10 Bps", mgr.humanReadable(10, "Bps"));
        assertEquals("1.0 MBps", mgr.humanReadable(1000000, "Bps"));
    }

    public void testCreateHighlights() {
        EasyMock.expect(linkService.getActiveLinks()).andReturn(List.of(LINK)).times(3);
        EasyMock.expect(hostService.getHosts()).andReturn(List.of(HOST)).times(3);
        EasyMock.expect(statisticService.getStats(H_KEY.id())).andReturn(S_MAP).times(6);
        EasyMock.replay(linkService);
        EasyMock.replay(hostService);
        EasyMock.replay(statisticService);

        mgr.allHighlighter.addHighlighter(H_KEY);
        Highlights h = mgr.allHighlighter.createHighlights();
        mgr.nameHighlighter.addHighlighter(H_KEY);
        mgr.nameHighlighter.createHighlights();
        mgr.trafficHighlighter.addHighlighter(H_KEY);
        mgr.trafficHighlighter.createHighlights();

        assertEquals(1, h.links().size());
        assertEquals(0, h.hosts().size());
        EasyMock.verify(linkService);
        EasyMock.verify(hostService);
        EasyMock.verify(statisticService);
    }
}
