// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.behaviour.upf;

import com.google.common.collect.ImmutableList;
import org.junit.Before;
import org.junit.Test;
import org.onlab.junit.TestUtils;
import org.onlab.util.HexString;
import org.onosproject.TestApplicationId;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;
import org.onosproject.net.behaviour.upf.*;
import org.onosproject.net.config.NetworkConfigService;
import org.onosproject.net.config.basics.BasicDeviceConfig;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.driver.DriverData;
import org.onosproject.net.driver.DriverHandler;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.pi.model.PiCounterModel;
import org.onosproject.net.pi.model.PiTableModel;
import org.onosproject.net.pi.service.PiPipeconfService;
import org.onosproject.net.pi.service.PiTranslationService;
import org.onosproject.p4runtime.api.P4RuntimeController;
import org.stratumproject.fabric.tna.PipeconfLoader;
import org.stratumproject.fabric.tna.behaviour.FabricCapabilities;
import org.stratumproject.fabric.tna.slicing.api.SlicingService;

import java.net.URI;
import java.nio.ByteBuffer;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.ConcurrentMap;

import static junit.framework.TestCase.assertNotNull;
import static junit.framework.TestCase.assertTrue;
import static org.easymock.EasyMock.anyString;
import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.stratumproject.fabric.tna.behaviour.Constants.TNA;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_EGRESS_SPGW_PDR_COUNTER;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_PDR_COUNTER;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_UPLINK_SESSIONS;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_DOWNLINK_SESSIONS;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_UPLINK_TERMINATIONS;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_DOWNLINK_TERMINATIONS;

public class FabricUpfProgrammableTest {

    private static final ApplicationId APP_ID =
            TestApplicationId.create(PipeconfLoader.APP_NAME);

    private MockPacketService packetService;
    private FabricUpfProgrammable upfProgrammable;

    // Bytes of a random but valid Ethernet frame.
    private static final byte[] ETH_FRAME_BYTES = HexString.fromHexString(
            "00060708090a0001020304058100000a08004500006a000100004011f92ec0a80001c0a8000204d2005" +
                    "00056a8d5000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20" +
                    "2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454" +
                    "64748494a4b4c4d", "");
    private static final TrafficTreatment TABLE_OUTPUT_TREATMENT = DefaultTrafficTreatment.builder()
            .setOutput(PortNumber.TABLE)
            .build();

    private static final List<PiTableModel> TABLE_MODELS = ImmutableList.of(
            new MockTableModel(FABRIC_INGRESS_SPGW_UPLINK_SESSIONS,
                               TestUpfConstants.PHYSICAL_MAX_UE_SESSIONS / 2),
            new MockTableModel(FABRIC_INGRESS_SPGW_DOWNLINK_SESSIONS,
                               TestUpfConstants.PHYSICAL_MAX_UE_SESSIONS / 2),
            new MockTableModel(FABRIC_INGRESS_SPGW_UPLINK_TERMINATIONS,
                               TestUpfConstants.PHYSICAL_MAX_UPF_TERMINATIONS / 2),
            new MockTableModel(FABRIC_INGRESS_SPGW_DOWNLINK_TERMINATIONS,
                               TestUpfConstants.PHYSICAL_MAX_UPF_TERMINATIONS / 2)
    );
    private static final List<PiCounterModel> COUNTER_MODELS = ImmutableList.of(
            new MockCounterModel(FABRIC_INGRESS_SPGW_PDR_COUNTER,
                                 TestUpfConstants.PHYSICAL_COUNTER_SIZE),
            new MockCounterModel(FABRIC_EGRESS_SPGW_PDR_COUNTER,
                                 TestUpfConstants.PHYSICAL_COUNTER_SIZE)
    );

    @Before
    public void setUp() throws Exception {
        FabricCapabilities capabilities = createMock(FabricCapabilities.class);
        expect(capabilities.supportUpf()).andReturn(true).anyTimes();
        replay(capabilities);

        // Services mock
        packetService = new MockPacketService();
        CoreService coreService = createMock(CoreService.class);
        NetworkConfigService netcfgService = createMock(NetworkConfigService.class);
        DeviceService deviceService = createMock(DeviceService.class);
        SlicingService slicingService = createMock(SlicingService.class);
        PiTranslationService piTranslationService = createMock(PiTranslationService.class);
        expect(coreService.getAppId(anyString())).andReturn(APP_ID).anyTimes();
        expect(netcfgService.getConfig(TestUpfConstants.DEVICE_ID, BasicDeviceConfig.class))
                .andReturn(TestUpfUtils.getBasicConfig(TestUpfConstants.DEVICE_ID, "/basic.json"))
                .anyTimes();
        replay(coreService, netcfgService);

        // Mock driverData to get the right device ID
        DriverData driverData = createMock(DriverData.class);
        expect(driverData.deviceId()).andReturn(TestUpfConstants.DEVICE_ID).anyTimes();
        replay(driverData);

        // Mock DriverHandler to get all the required mocked services
        DriverHandler driverHandler = createMock(DriverHandler.class);
        expect(driverHandler.get(FlowRuleService.class)).andReturn(new MockFlowRuleService()).anyTimes();
        expect(driverHandler.get(SlicingService.class)).andReturn(slicingService).anyTimes();
        expect(driverHandler.get(PacketService.class)).andReturn(packetService).anyTimes();
        expect(driverHandler.get(NetworkConfigService.class)).andReturn(netcfgService).anyTimes();
        expect(driverHandler.get(CoreService.class)).andReturn(coreService).anyTimes();
        expect(driverHandler.get(DeviceService.class)).andReturn(deviceService).anyTimes();
        expect(driverHandler.get(PiTranslationService.class)).andReturn(piTranslationService).anyTimes();
        expect(driverHandler.get(PiPipeconfService.class))
                .andReturn(new MockPiPipeconfService(TABLE_MODELS, COUNTER_MODELS, TNA))
                .anyTimes();
        expect(driverHandler.get(P4RuntimeController.class))
                .andReturn(new MockP4RuntimeController(TestUpfConstants.DEVICE_ID,
                                                       TestUpfConstants.COUNTER_PKTS,
                                                       TestUpfConstants.COUNTER_BYTES,
                                                       TestUpfConstants.PHYSICAL_COUNTER_SIZE))
                .anyTimes();
        expect(driverHandler.data()).andReturn(driverData).anyTimes();
        replay(driverHandler);

        upfProgrammable = new FabricUpfProgrammable();
        TestUtils.setField(upfProgrammable, "handler", driverHandler);
        TestUtils.setField(upfProgrammable, "data", driverData);
        ConcurrentMap<DeviceId, URI> channelUris = TestUtils.getField(upfProgrammable, "CHANNEL_URIS");
        channelUris.put(TestUpfConstants.DEVICE_ID, new URI("grpc://localhost:1234?device_id=1"));
    }

    @Test
    public void testUplinkUeSession() throws Exception {
        assertTrue(upfProgrammable.readUpfEntities(UpfEntityType.SESSION).isEmpty());
        UeSession expectedUeSession = TestUpfConstants.UPLINK_UE_SESSION;
        upfProgrammable.applyUpfEntity(expectedUeSession);
        Collection<UpfEntity> installedUeSessions = upfProgrammable.readUpfEntities(UpfEntityType.SESSION);
        assertThat(installedUeSessions.size(), equalTo(1));
        for (var readUeSession : installedUeSessions) {
            assertThat(readUeSession, equalTo(expectedUeSession));
        }
        upfProgrammable.deleteUpfEntity(expectedUeSession);
        assertTrue(upfProgrammable.readUpfEntities(UpfEntityType.SESSION).isEmpty());
    }

    @Test
    public void testDownlinkUeSession() throws Exception {
        assertTrue(upfProgrammable.readUpfEntities(UpfEntityType.SESSION).isEmpty());
        UeSession expectedUeSession = TestUpfConstants.DOWNLINK_UE_SESSION;
        upfProgrammable.applyUpfEntity(expectedUeSession);
        Collection<UpfEntity> installedUeSessions = upfProgrammable.readUpfEntities(UpfEntityType.SESSION);
        assertThat(installedUeSessions.size(), equalTo(1));
        for (var readUeSession : installedUeSessions) {
            assertThat(readUeSession, equalTo(expectedUeSession));
        }
        upfProgrammable.deleteUpfEntity(expectedUeSession);
        assertTrue(upfProgrammable.readUpfEntities(UpfEntityType.SESSION).isEmpty());
    }

    @Test
    public void testUplinkUpfTermination() throws Exception {
        assertTrue(upfProgrammable.readUpfEntities(UpfEntityType.TERMINATION).isEmpty());
        UpfTermination expected = TestUpfConstants.UPLINK_UPF_TERMINATION;
        upfProgrammable.applyUpfEntity(expected);
        Collection<UpfEntity> installedUpfTerminations = upfProgrammable.readUpfEntities(UpfEntityType.TERMINATION);
        assertThat(installedUpfTerminations.size(), equalTo(1));
        for (var readUpfTermination : installedUpfTerminations) {
            assertThat(readUpfTermination, equalTo(expected));
        }
        upfProgrammable.deleteUpfEntity(expected);
        assertTrue(upfProgrammable.readUpfEntities(UpfEntityType.TERMINATION).isEmpty());
    }

    @Test
    public void testDownlinkUpfTermination() throws Exception {
        assertTrue(upfProgrammable.readUpfEntities(UpfEntityType.TERMINATION).isEmpty());
        UpfTermination expected = TestUpfConstants.DOWNLINK_UPF_TERMINATION;
        upfProgrammable.applyUpfEntity(expected);
        Collection<UpfEntity> installedUpfTerminations = upfProgrammable.readUpfEntities(UpfEntityType.TERMINATION);
        assertThat(installedUpfTerminations.size(), equalTo(1));
        for (var readUpfTermination : installedUpfTerminations) {
            assertThat(readUpfTermination, equalTo(expected));
        }
        upfProgrammable.deleteUpfEntity(expected);
        assertTrue(upfProgrammable.readUpfEntities(UpfEntityType.TERMINATION).isEmpty());
    }

    @Test
    public void testUplinkInterface() throws Exception {
        assertTrue(upfProgrammable.readUpfEntities(UpfEntityType.INTERFACE).isEmpty());
        UpfInterface expectedInterface = TestUpfConstants.UPLINK_INTERFACE;
        upfProgrammable.applyUpfEntity(expectedInterface);
        Collection<UpfEntity> installedInterfaces = upfProgrammable.readUpfEntities(UpfEntityType.INTERFACE);
        assertThat(installedInterfaces.size(), equalTo(1));
        for (var readInterface : installedInterfaces) {
            assertThat(readInterface, equalTo(expectedInterface));
        }
        upfProgrammable.deleteUpfEntity(expectedInterface);
        assertTrue(upfProgrammable.readUpfEntities(UpfEntityType.INTERFACE).isEmpty());
    }

    @Test
    public void testDownlinkInterface() throws Exception {
        assertTrue(upfProgrammable.readUpfEntities(UpfEntityType.INTERFACE).isEmpty());
        UpfInterface expectedInterface = TestUpfConstants.DOWNLINK_INTERFACE;
        upfProgrammable.applyUpfEntity(expectedInterface);
        Collection<UpfEntity> installedInterfaces = upfProgrammable.readUpfEntities(UpfEntityType.INTERFACE);
        assertThat(installedInterfaces.size(), equalTo(1));
        for (var readInterface : installedInterfaces) {
            assertThat(readInterface, equalTo(expectedInterface));
        }
        upfProgrammable.deleteUpfEntity(expectedInterface);
        assertTrue(upfProgrammable.readUpfEntities(UpfEntityType.INTERFACE).isEmpty());
    }

    @Test
    public void testClearInterfaces() throws Exception {
        // FIXME: UpfProgrammableAPI doesn't currently provide a way to clear just interfaces.
        //        assertTrue(upfProgrammable.getInterfaces().isEmpty());
        //        upfProgrammable.addInterface(TestUpfConstants.UPLINK_INTERFACE);
        //        upfProgrammable.addInterface(TestUpfConstants.DOWNLINK_INTERFACE);
        //        assertThat(upfProgrammable.getInterfaces().size(), equalTo(2));
        //        upfProgrammable.clearInterfaces();
        //        assertTrue(upfProgrammable.getInterfaces().isEmpty());
    }

    @Test
    public void testReadAllCounters() throws Exception {
        Collection<UpfEntity> allStats = upfProgrammable.readUpfEntities(UpfEntityType.COUNTER, -1);
        assertThat(allStats.size(), equalTo(TestUpfConstants.PHYSICAL_COUNTER_SIZE));
        for (UpfEntity entity : allStats) {
            UpfCounter stat = (UpfCounter) entity;
            assertThat(stat.getIngressBytes(), equalTo(TestUpfConstants.COUNTER_BYTES));
            assertThat(stat.getEgressBytes(), equalTo(TestUpfConstants.COUNTER_BYTES));
            assertThat(stat.getIngressPkts(), equalTo(TestUpfConstants.COUNTER_PKTS));
            assertThat(stat.getEgressPkts(), equalTo(TestUpfConstants.COUNTER_PKTS));
        }
    }

    @Test
    public void testReadAllCountersLimitedCounters() throws Exception {
        Collection<UpfEntity> allStats = upfProgrammable.readUpfEntities(UpfEntityType.COUNTER, 10);
        assertThat(allStats.size(), equalTo(10));
    }

    @Test
    public void testReadAllCountersPhysicalLimit() throws Exception {
        Collection<UpfEntity> allStats = upfProgrammable.readUpfEntities(UpfEntityType.COUNTER, 1024);
        assertThat(allStats.size(), equalTo(TestUpfConstants.PHYSICAL_COUNTER_SIZE));
    }

    @Test
    public void testSendPacketOut() {
        upfProgrammable.sendPacketOut(ByteBuffer.wrap(ETH_FRAME_BYTES));
        var emittedPkt = packetService.emittedPackets.poll();
        assertNotNull(emittedPkt);
        assertThat(emittedPkt.data().array(), equalTo(ETH_FRAME_BYTES));
        assertThat(emittedPkt.treatment(), equalTo(TABLE_OUTPUT_TREATMENT));
    }
}
