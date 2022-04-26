// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0
package org.stratumproject.fabric.tna.behaviour.upf;

import com.google.common.collect.ImmutableList;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.onlab.junit.TestUtils;
import org.onlab.packet.Ip4Prefix;
import org.onlab.util.HexString;
import org.onosproject.TestApplicationId;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;
import org.onosproject.net.behaviour.upf.UpfApplication;
import org.onosproject.net.behaviour.upf.UpfCounter;
import org.onosproject.net.behaviour.upf.UpfEntity;
import org.onosproject.net.behaviour.upf.UpfEntityType;
import org.onosproject.net.behaviour.upf.UpfInterface;
import org.onosproject.net.behaviour.upf.UpfMeter;
import org.onosproject.net.behaviour.upf.UpfProgrammableException;
import org.onosproject.net.behaviour.upf.UpfSessionDownlink;
import org.onosproject.net.behaviour.upf.UpfSessionUplink;
import org.onosproject.net.behaviour.upf.UpfTerminationDownlink;
import org.onosproject.net.behaviour.upf.UpfTerminationUplink;
import org.onosproject.net.config.NetworkConfigService;
import org.onosproject.net.config.basics.BasicDeviceConfig;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.driver.DriverData;
import org.onosproject.net.driver.DriverHandler;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.meter.MeterService;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.pi.model.PiCounterModel;
import org.onosproject.net.pi.model.PiMeterModel;
import org.onosproject.net.pi.model.PiTableModel;
import org.onosproject.net.pi.service.PiPipeconfService;
import org.onosproject.net.pi.service.PiTranslationService;
import org.onosproject.p4runtime.api.P4RuntimeController;
import org.stratumproject.fabric.tna.Constants;
import org.stratumproject.fabric.tna.behaviour.FabricCapabilities;
import org.stratumproject.fabric.tna.slicing.api.SliceId;
import org.stratumproject.fabric.tna.slicing.api.SlicingService;
import org.stratumproject.fabric.tna.slicing.api.TrafficClass;

import java.net.URI;
import java.nio.ByteBuffer;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentMap;

import static junit.framework.TestCase.assertNotNull;
import static junit.framework.TestCase.assertTrue;
import static org.easymock.EasyMock.anyString;
import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.stratumproject.fabric.tna.Constants.TNA;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_EGRESS_UPF_EG_TUNNEL_PEERS;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_EGRESS_UPF_TERMINATIONS_COUNTER;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_QOS_SLICE_TC_METER;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_UPF_APPLICATIONS;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_UPF_APP_METER;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_UPF_DOWNLINK_SESSIONS;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_UPF_DOWNLINK_TERMINATIONS;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_UPF_IG_TUNNEL_PEERS;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_UPF_SESSION_METER;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_UPF_TERMINATIONS_COUNTER;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_UPF_UPLINK_SESSIONS;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_UPF_UPLINK_TERMINATIONS;
import static org.stratumproject.fabric.tna.behaviour.upf.TestUpfConstants.DL_COUNTER_BYTES;
import static org.stratumproject.fabric.tna.behaviour.upf.TestUpfConstants.DL_COUNTER_PKTS;
import static org.stratumproject.fabric.tna.behaviour.upf.TestUpfConstants.DOWNLINK_COUNTER;
import static org.stratumproject.fabric.tna.behaviour.upf.TestUpfConstants.SLICE_MOBILE;
import static org.stratumproject.fabric.tna.behaviour.upf.TestUpfConstants.UL_COUNTER_BYTES;
import static org.stratumproject.fabric.tna.behaviour.upf.TestUpfConstants.UL_COUNTER_PKTS;
import static org.stratumproject.fabric.tna.behaviour.upf.TestUpfConstants.UPLINK_COUNTER;
import static org.stratumproject.fabric.tna.behaviour.upf.TestUpfConstants.ZERO_DOWNLINK_COUNTER;
import static org.stratumproject.fabric.tna.behaviour.upf.TestUpfConstants.ZERO_UPLINK_COUNTER;

public class FabricUpfProgrammableTest {

    private static final ApplicationId APP_ID =
            TestApplicationId.create(Constants.APP_NAME);

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
            new MockTableModel(FABRIC_INGRESS_UPF_UPLINK_SESSIONS,
                               TestUpfConstants.PHYSICAL_MAX_UE_SESSIONS / 2),
            new MockTableModel(FABRIC_INGRESS_UPF_DOWNLINK_SESSIONS,
                               TestUpfConstants.PHYSICAL_MAX_UE_SESSIONS / 2),
            new MockTableModel(FABRIC_INGRESS_UPF_UPLINK_TERMINATIONS,
                               TestUpfConstants.PHYSICAL_MAX_UPF_TERMINATIONS / 2),
            new MockTableModel(FABRIC_INGRESS_UPF_DOWNLINK_TERMINATIONS,
                               TestUpfConstants.PHYSICAL_MAX_UPF_TERMINATIONS / 2),
            new MockTableModel(FABRIC_INGRESS_UPF_IG_TUNNEL_PEERS,
                               TestUpfConstants.PHYSICAL_MAX_TUNNELS),
            new MockTableModel(FABRIC_EGRESS_UPF_EG_TUNNEL_PEERS,
                               TestUpfConstants.PHYSICAL_MAX_TUNNELS),
            new MockTableModel(FABRIC_INGRESS_UPF_APPLICATIONS,
                               TestUpfConstants.PHYSICAL_MAX_APPLICATIONS)
    );
    private static final List<PiCounterModel> COUNTER_MODELS = ImmutableList.of(
            new MockCounterModel(FABRIC_INGRESS_UPF_TERMINATIONS_COUNTER,
                                 TestUpfConstants.PHYSICAL_COUNTER_SIZE),
            new MockCounterModel(FABRIC_EGRESS_UPF_TERMINATIONS_COUNTER,
                                 TestUpfConstants.PHYSICAL_COUNTER_SIZE)
    );
    private static final List<PiMeterModel> METER_MODELS = ImmutableList.of(
            new MockMeterModel(FABRIC_INGRESS_UPF_SESSION_METER,
                               TestUpfConstants.PHYSICAL_SESSION_METER_SIZE),
            new MockMeterModel(FABRIC_INGRESS_UPF_APP_METER,
                               TestUpfConstants.PHYSICAL_APP_METER_SIZE),
            new MockMeterModel(FABRIC_INGRESS_QOS_SLICE_TC_METER,
                               TestUpfConstants.PHYSICAL_MAX_SLICE_METERS)
    );

    @Rule
    public ExpectedException exceptionRule = ExpectedException.none();

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
        expect(slicingService.getSlices()).andReturn(Set.of(SliceId.of(SLICE_MOBILE))).anyTimes();
        expect(slicingService.getTrafficClasses(SliceId.of(SLICE_MOBILE)))
                .andReturn(Set.of(TrafficClass.ELASTIC)).anyTimes();
        PiTranslationService piTranslationService = createMock(PiTranslationService.class);
        expect(coreService.getAppId(anyString())).andReturn(APP_ID).anyTimes();
        expect(netcfgService.getConfig(TestUpfConstants.DEVICE_ID, BasicDeviceConfig.class))
                .andReturn(TestUpfUtils.getBasicConfig(TestUpfConstants.DEVICE_ID, "/basic.json"))
                .anyTimes();
        replay(coreService, netcfgService, slicingService);

        // Mock driverData to get the right device ID
        DriverData driverData = createMock(DriverData.class);
        expect(driverData.deviceId()).andReturn(TestUpfConstants.DEVICE_ID).anyTimes();
        replay(driverData);

        // Mock DriverHandler to get all the required mocked services
        DriverHandler driverHandler = createMock(DriverHandler.class);
        expect(driverHandler.get(FlowRuleService.class)).andReturn(new MockFlowRuleService()).anyTimes();
        expect(driverHandler.get(MeterService.class)).andReturn(new MockMeterService()).anyTimes();
        expect(driverHandler.get(SlicingService.class)).andReturn(slicingService).anyTimes();
        expect(driverHandler.get(PacketService.class)).andReturn(packetService).anyTimes();
        expect(driverHandler.get(NetworkConfigService.class)).andReturn(netcfgService).anyTimes();
        expect(driverHandler.get(CoreService.class)).andReturn(coreService).anyTimes();
        expect(driverHandler.get(DeviceService.class)).andReturn(deviceService).anyTimes();
        expect(driverHandler.get(PiTranslationService.class)).andReturn(piTranslationService).anyTimes();
        expect(driverHandler.get(PiPipeconfService.class))
                .andReturn(new MockPiPipeconfService(
                        TABLE_MODELS, COUNTER_MODELS, METER_MODELS, TNA))
                .anyTimes();
        expect(driverHandler.get(P4RuntimeController.class))
                .andReturn(new MockP4RuntimeController(TestUpfConstants.DEVICE_ID,
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
        assertTrue(upfProgrammable.readAll(UpfEntityType.SESSION_UPLINK).isEmpty());
        UpfSessionUplink expectedUeSession = TestUpfConstants.UPLINK_UE_SESSION;
        upfProgrammable.apply(expectedUeSession);
        Collection<? extends UpfEntity> installedUeSessions = upfProgrammable.readAll(UpfEntityType.SESSION_UPLINK);
        assertThat(installedUeSessions.size(), equalTo(1));
        for (var readUeSession : installedUeSessions) {
            assertThat(readUeSession, equalTo(expectedUeSession));
        }
        upfProgrammable.delete(expectedUeSession);
        assertTrue(upfProgrammable.readAll(UpfEntityType.SESSION_UPLINK).isEmpty());
    }

    @Test
    public void testDownlinkUeSession() throws Exception {
        assertTrue(upfProgrammable.readAll(UpfEntityType.SESSION_DOWNLINK).isEmpty());
        UpfSessionDownlink expectedUeSession = TestUpfConstants.DOWNLINK_UE_SESSION;
        upfProgrammable.apply(expectedUeSession);
        Collection<? extends UpfEntity> installedUeSessions = upfProgrammable.readAll(UpfEntityType.SESSION_DOWNLINK);
        assertThat(installedUeSessions.size(), equalTo(1));
        for (var readUeSession : installedUeSessions) {
            assertThat(readUeSession, equalTo(expectedUeSession));
        }
        upfProgrammable.delete(expectedUeSession);
        assertTrue(upfProgrammable.readAll(UpfEntityType.SESSION_DOWNLINK).isEmpty());
    }

    @Test
    public void testUplinkUpfTermination() throws Exception {
        assertTrue(upfProgrammable.readAll(UpfEntityType.TERMINATION_UPLINK).isEmpty());
        UpfTerminationUplink expected = TestUpfConstants.UPLINK_UPF_TERMINATION;
        upfProgrammable.apply(expected);
        Collection<? extends UpfEntity> installedUpfTerminations =
                upfProgrammable.readAll(UpfEntityType.TERMINATION_UPLINK);
        assertThat(installedUpfTerminations.size(), equalTo(1));
        for (var readUpfTermination : installedUpfTerminations) {
            assertThat(readUpfTermination, equalTo(expected));
        }
        upfProgrammable.delete(expected);
        assertTrue(upfProgrammable.readAll(UpfEntityType.TERMINATION_UPLINK).isEmpty());
    }

    @Test
    public void testDownlinkUpfTermination() throws Exception {
        assertTrue(upfProgrammable.readAll(UpfEntityType.TERMINATION_DOWNLINK).isEmpty());
        UpfTerminationDownlink expected = TestUpfConstants.DOWNLINK_UPF_TERMINATION;
        upfProgrammable.apply(expected);
        Collection<? extends UpfEntity> installedUpfTerminations =
                upfProgrammable.readAll(UpfEntityType.TERMINATION_DOWNLINK);
        assertThat(installedUpfTerminations.size(), equalTo(1));
        for (var readUpfTermination : installedUpfTerminations) {
            assertThat(readUpfTermination, equalTo(expected));
        }
        upfProgrammable.delete(expected);
        assertTrue(upfProgrammable.readAll(UpfEntityType.TERMINATION_DOWNLINK).isEmpty());
    }

    @Test
    public void testUplinkInterface() throws Exception {
        assertTrue(upfProgrammable.readAll(UpfEntityType.INTERFACE).isEmpty());
        UpfInterface expectedInterface = TestUpfConstants.UPLINK_INTERFACE;
        upfProgrammable.apply(expectedInterface);
        Collection<? extends UpfEntity> installedInterfaces =
                upfProgrammable.readAll(UpfEntityType.INTERFACE);
        assertThat(installedInterfaces.size(), equalTo(1));
        for (var readInterface : installedInterfaces) {
            assertThat(readInterface, equalTo(expectedInterface));
        }
        upfProgrammable.delete(expectedInterface);
        assertTrue(upfProgrammable.readAll(UpfEntityType.INTERFACE).isEmpty());
    }

    @Test
    public void testDownlinkInterface() throws Exception {
        assertTrue(upfProgrammable.readAll(UpfEntityType.INTERFACE).isEmpty());
        UpfInterface expectedInterface = TestUpfConstants.DOWNLINK_INTERFACE;
        upfProgrammable.apply(expectedInterface);
        Collection<? extends UpfEntity> installedInterfaces =
                upfProgrammable.readAll(UpfEntityType.INTERFACE);
        assertThat(installedInterfaces.size(), equalTo(1));
        for (var readInterface : installedInterfaces) {
            assertThat(readInterface, equalTo(expectedInterface));
        }
        upfProgrammable.delete(expectedInterface);
        assertTrue(upfProgrammable.readAll(UpfEntityType.INTERFACE).isEmpty());
    }

    @Test
    public void testInvalidSliceIdInterface() throws Exception {
        exceptionRule.expect(UpfProgrammableException.class);
        exceptionRule.expectMessage("Provided slice ID (0) is not available in slicing service!");
        assertTrue(upfProgrammable.readAll(UpfEntityType.INTERFACE).isEmpty());
        upfProgrammable.apply(UpfInterface.createUePoolFrom(Ip4Prefix.valueOf("10.0.0.0/24"), 0));
    }

    @Test
    public void testUpfApplication() throws Exception {
        assertTrue(upfProgrammable.readAll(UpfEntityType.APPLICATION).isEmpty());
        UpfApplication expectedAppFiltering = TestUpfConstants.APPLICATION_FILTERING;
        upfProgrammable.apply(expectedAppFiltering);
        Collection<? extends UpfEntity> installedAppFiltering =
                upfProgrammable.readAll(UpfEntityType.APPLICATION);
        assertThat(installedAppFiltering.size(), equalTo(1));
        for (var readAppFiltering : installedAppFiltering) {
            assertThat(readAppFiltering, equalTo(expectedAppFiltering));
        }
        upfProgrammable.delete(expectedAppFiltering);
        assertTrue(upfProgrammable.readAll(UpfEntityType.APPLICATION).isEmpty());
    }

    @Test
    public void testInvalidSliceIdUpfApplication() throws Exception {
        exceptionRule.expect(UpfProgrammableException.class);
        exceptionRule.expectMessage("Provided slice ID (0) is not available in slicing service!");
        assertTrue(upfProgrammable.readAll(UpfEntityType.INTERFACE).isEmpty());
        upfProgrammable.apply(TestUpfConstants.APPLICATION_FILTERING_INVALID_SLICE_ID);
    }

    @Test
    public void testUpfMeter() throws Exception {
        // Application meters
        assertTrue(upfProgrammable.readAll(UpfEntityType.APPLICATION_METER).isEmpty());
        UpfMeter expectedAppMeter = TestUpfConstants.APP_METER;
        upfProgrammable.apply(expectedAppMeter);
        Collection<? extends UpfEntity> installedAppMeters =
                upfProgrammable.readAll(UpfEntityType.APPLICATION_METER);
        assertThat(installedAppMeters.size(), equalTo(1));
        for (var readAppMeter : installedAppMeters) {
            assertThat(readAppMeter, equalTo(expectedAppMeter));
        }
        upfProgrammable.apply(TestUpfConstants.APP_METER_RESET);
        assertTrue(upfProgrammable.readAll(UpfEntityType.APPLICATION_METER).isEmpty());

        // Session Meters
        assertTrue(upfProgrammable.readAll(UpfEntityType.SESSION_METER).isEmpty());
        UpfMeter expectedSessionMeter = TestUpfConstants.SESSION_METER;
        upfProgrammable.apply(expectedSessionMeter);
        Collection<? extends UpfEntity> installedSessionMeters =
                upfProgrammable.readAll(UpfEntityType.SESSION_METER);
        assertThat(installedSessionMeters.size(), equalTo(1));
        for (var readSessionMeter : installedSessionMeters) {
            assertThat(readSessionMeter, equalTo(expectedSessionMeter));
        }
        upfProgrammable.apply(TestUpfConstants.SESSION_METER_RESET);
        assertTrue(upfProgrammable.readAll(UpfEntityType.SESSION_METER).isEmpty());
    }

    @Test
    public void testSliceMeter() throws Exception {
        // Slice Meters
        assertTrue(upfProgrammable.readAll(UpfEntityType.SLICE_METER).isEmpty());
        UpfMeter expectedSliceMeter = TestUpfConstants.SLICE_METER;
        upfProgrammable.apply(expectedSliceMeter);
        Collection<? extends UpfEntity> installedSliceMeters =
                upfProgrammable.readAll(UpfEntityType.SLICE_METER);
        assertThat(installedSliceMeters.size(), equalTo(1));
        for (var readSliceMeter : installedSliceMeters) {
            assertThat(readSliceMeter, equalTo(expectedSliceMeter));
        }
        upfProgrammable.apply(TestUpfConstants.SLICE_METER_RESET);
        assertTrue(upfProgrammable.readAll(UpfEntityType.SLICE_METER).isEmpty());
    }

    @Test
    public void testApplyCounter() throws Exception {
        assertThat(
                upfProgrammable.readCounter(TestUpfConstants.UPLINK_COUNTER.getCellId()),
                equalTo(ZERO_UPLINK_COUNTER)
        );
        UpfCounter expectedCounter = TestUpfConstants.UPLINK_COUNTER;
        upfProgrammable.apply(expectedCounter);
        UpfCounter installedCounter =
                upfProgrammable.readCounter(expectedCounter.getCellId());
        assertThat(installedCounter, equalTo(expectedCounter));
        upfProgrammable.apply(ZERO_UPLINK_COUNTER);
        assertThat(
                upfProgrammable.readCounter(TestUpfConstants.UPLINK_COUNTER.getCellId()),
                equalTo(ZERO_UPLINK_COUNTER)
        );
    }

    @Test
    public void testInvalidSliceIdSliceMeter() throws Exception {
        exceptionRule.expect(UpfProgrammableException.class);
        exceptionRule.expectMessage("Provided slice ID (0) is not available in slicing service!");
        assertTrue(upfProgrammable.readAll(UpfEntityType.SLICE_METER).isEmpty());
        upfProgrammable.apply(TestUpfConstants.SLICE_METER_INVALID_SLICE_ID);
    }

    @Test
    public void testInvalidTrafficClassSliceMeter() throws Exception {
        exceptionRule.expect(UpfProgrammableException.class);
        exceptionRule.expectMessage(
                "Provided traffic class (BEST_EFFORT) is not available for provided slice ID (10) in slicing service!");
        assertTrue(upfProgrammable.readAll(UpfEntityType.SLICE_METER).isEmpty());
        upfProgrammable.apply(TestUpfConstants.SLICE_METER_INVALID_TC);
    }

    @Test
    public void testClearInterfaces() throws Exception {
        assertTrue(upfProgrammable.readAll(UpfEntityType.INTERFACE).isEmpty());
        upfProgrammable.apply(TestUpfConstants.UPLINK_INTERFACE);
        upfProgrammable.apply(TestUpfConstants.DOWNLINK_INTERFACE);
        assertThat(upfProgrammable.readAll(UpfEntityType.INTERFACE).size(), equalTo(2));
        upfProgrammable.deleteAll(UpfEntityType.INTERFACE);
        assertTrue(upfProgrammable.readAll(UpfEntityType.INTERFACE).isEmpty());
    }

    @Test
    public void testReadAllCounters() throws Exception {
        assertAllZeroCounters();

        upfProgrammable.apply(UPLINK_COUNTER);
        upfProgrammable.apply(DOWNLINK_COUNTER);
        Collection<? extends UpfEntity> allStats = upfProgrammable.readAll(UpfEntityType.COUNTER);
        assertThat(allStats.size(), equalTo(TestUpfConstants.PHYSICAL_COUNTER_SIZE));
        for (UpfEntity entity : allStats) {
            UpfCounter stat = (UpfCounter) entity;
            if (stat.getCellId() == UPLINK_COUNTER.getCellId()) {
                assertThat(stat.getIngressBytes(), equalTo(UL_COUNTER_BYTES));
                assertThat(stat.getEgressBytes(), equalTo(UL_COUNTER_BYTES));
                assertThat(stat.getIngressPkts(), equalTo(UL_COUNTER_PKTS));
                assertThat(stat.getEgressPkts(), equalTo(UL_COUNTER_PKTS));
            } else if (stat.getCellId() == DOWNLINK_COUNTER.getCellId()) {
                assertThat(stat.getIngressBytes(), equalTo(DL_COUNTER_BYTES));
                assertThat(stat.getEgressBytes(), equalTo(DL_COUNTER_BYTES));
                assertThat(stat.getIngressPkts(), equalTo(DL_COUNTER_PKTS));
                assertThat(stat.getEgressPkts(), equalTo(UL_COUNTER_PKTS));
            } else {
                assertThat(stat.getIngressBytes(), equalTo(0L));
                assertThat(stat.getEgressBytes(), equalTo(0L));
                assertThat(stat.getIngressPkts(), equalTo(0L));
                assertThat(stat.getEgressPkts(), equalTo(0L));
            }
        }

        upfProgrammable.apply(ZERO_UPLINK_COUNTER);
        upfProgrammable.apply(ZERO_DOWNLINK_COUNTER);
        assertAllZeroCounters();
    }

    private void assertAllZeroCounters() throws UpfProgrammableException {
        Collection<? extends UpfEntity> allStats = upfProgrammable.readAll(UpfEntityType.COUNTER);
        assertThat(allStats.size(), equalTo(TestUpfConstants.PHYSICAL_COUNTER_SIZE));
        for (UpfEntity entity : allStats) {
            UpfCounter stat = (UpfCounter) entity;
            assertThat(stat.getIngressBytes(), equalTo(0L));
            assertThat(stat.getEgressBytes(), equalTo(0L));
            assertThat(stat.getIngressPkts(), equalTo(0L));
            assertThat(stat.getEgressPkts(), equalTo(0L));
        }
    }

    @Test
    public void testReadAllCountersLimitedCounters() throws Exception {
        Collection<UpfCounter> allStats = upfProgrammable.readCounters(10);
        assertThat(allStats.size(), equalTo(10));
    }

    @Test
    public void testReadAllCountersPhysicalLimit() throws Exception {
        Collection<UpfCounter> allStats = upfProgrammable.readCounters(1024);
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
