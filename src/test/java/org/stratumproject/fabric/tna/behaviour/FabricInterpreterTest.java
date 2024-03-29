// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0
package org.stratumproject.fabric.tna.behaviour;

import com.google.common.collect.ImmutableList;
import org.junit.Before;
import org.junit.Test;
import org.onlab.packet.Data;
import org.onlab.packet.Ethernet;
import org.onlab.packet.MacAddress;
import org.onlab.packet.MplsLabel;
import org.onlab.packet.VlanId;
import org.onlab.util.ImmutableByteSequence;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Port;
import org.onosproject.net.PortNumber;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.driver.DriverData;
import org.onosproject.net.driver.DriverHandler;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.packet.DefaultInboundPacket;
import org.onosproject.net.packet.DefaultOutboundPacket;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.pi.model.PiPacketOperationType;
import org.onosproject.net.pi.model.PiPipeconf;
import org.onosproject.net.pi.model.PiPipelineInterpreter;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiActionParam;
import org.onosproject.net.pi.runtime.PiPacketMetadata;
import org.onosproject.net.pi.runtime.PiPacketOperation;
import org.onosproject.net.pi.service.PiPipeconfService;
import org.stratumproject.fabric.tna.Constants;
import org.stratumproject.fabric.tna.slicing.api.SlicingService;
import org.stratumproject.fabric.tna.slicing.api.TrafficClassDescription;

import java.nio.ByteBuffer;
import java.util.Collection;
import java.util.Optional;

import static org.easymock.EasyMock.createNiceMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.junit.Assert.assertEquals;

/**
 * Test for fabric interpreter.
 */
public class FabricInterpreterTest {
    private static final VlanId VLAN_100 = VlanId.vlanId("100");
    private static final PortNumber PORT_1 = PortNumber.portNumber(1);
    private static final MacAddress SRC_MAC = MacAddress.valueOf("00:00:00:00:00:01");
    private static final MacAddress DST_MAC = MacAddress.valueOf("00:00:00:00:00:02");
    private static final MplsLabel MPLS_10 = MplsLabel.mplsLabel(10);
    private static final DeviceId DEVICE_ID = DeviceId.deviceId("device:1");
    private static final int SYSTEM_QUEUE_ID = TrafficClassDescription.BEST_EFFORT.queueId().id();

    private FabricInterpreter interpreter;
    private DeviceService deviceService;

    @Before
    public void setup() {
        DriverData data = createNiceMock(DriverData.class);
        expect(data.deviceId()).andReturn(DEVICE_ID).anyTimes();
        replay(data);

        PiPipeconf piPipeconf = createNiceMock(PiPipeconf.class);

        PiPipeconfService piPipeconfService = createNiceMock(PiPipeconfService.class);
        expect(piPipeconfService.getPipeconf(DEVICE_ID)).andReturn(Optional.of(piPipeconf));
        replay(piPipeconfService);

        SlicingService slicingService = createNiceMock(SlicingService.class);
        expect(slicingService.getSystemTrafficClass()).andReturn(TrafficClassDescription.BEST_EFFORT);
        replay(slicingService);

        DriverHandler handler = createNiceMock(DriverHandler.class);
        deviceService = createNiceMock(DeviceService.class);
        expect(handler.get(DeviceService.class)).andReturn(deviceService).anyTimes();
        expect(handler.data()).andReturn(data).anyTimes();
        expect(handler.get(PiPipeconfService.class)).andReturn(piPipeconfService).anyTimes();
        expect(handler.get(SlicingService.class)).andReturn(slicingService).once();
        replay(handler);

        interpreter = new FabricInterpreter();
        interpreter.setHandler(handler);
    }

    /* Forwarding control block */

    /**
     * Map empty treatment to NOP for routing v4 table.
     */
    @Test
    public void testRoutingV4TreatmentEmpty() throws Exception {
        TrafficTreatment treatment = DefaultTrafficTreatment.emptyTreatment();
        PiAction mappedAction = interpreter.mapTreatment(
                treatment, P4InfoConstants.FABRIC_INGRESS_FORWARDING_ROUTING_V4);
        PiAction expectedAction = PiAction.builder()
                .withId(P4InfoConstants.FABRIC_INGRESS_FORWARDING_NOP_ROUTING_V4)
                .build();
        assertEquals(expectedAction, mappedAction);
    }

    /**
     * Map wipeDeferred treatment to DROP for routing v4 table.
     */
    @Test
    public void testRoutingV4TreatmentCleared() throws Exception {
        TrafficTreatment treatment = DefaultTrafficTreatment.builder().wipeDeferred().build();
        PiAction mappedAction = interpreter.mapTreatment(
                treatment, P4InfoConstants.FABRIC_INGRESS_FORWARDING_ROUTING_V4);
        PiAction expectedAction = PiAction.builder()
                .withId(P4InfoConstants.FABRIC_INGRESS_FORWARDING_DROP_ROUTING_V4)
                .build();
        assertEquals(expectedAction, mappedAction);
    }

    /**
     * Map empty treatment to NOP for ACL table.
     */
    @Test
    public void testAclTreatmentEmpty() throws Exception {
        TrafficTreatment treatment = DefaultTrafficTreatment.emptyTreatment();
        PiAction mappedAction = interpreter.mapTreatment(
                treatment, P4InfoConstants.FABRIC_INGRESS_ACL_ACL);
        PiAction expectedAction = PiAction.builder()
                .withId(P4InfoConstants.FABRIC_INGRESS_ACL_NOP_ACL)
                .build();
        assertEquals(expectedAction, mappedAction);
    }

    /**
     * Map wipeDeferred treatment to DROP for ACL table.
     */
    @Test
    public void testAclTreatmentWipeDeferred() throws Exception {
        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .wipeDeferred()
                .build();
        PiAction mappedAction = interpreter.mapTreatment(
                treatment, P4InfoConstants.FABRIC_INGRESS_ACL_ACL);
        PiAction expectedAction = PiAction.builder()
                .withId(P4InfoConstants.FABRIC_INGRESS_ACL_DROP)
                .build();
        assertEquals(expectedAction, mappedAction);
    }

    /* Next control block */

    // TODO: add profile with simple next or remove test
    // /**
    //  * Map treatment to output action for simple next.
    //  */
    // @Test
    // public void testNextTreatmentSimpleOutput() throws Exception {
    //     TrafficTreatment treatment = DefaultTrafficTreatment.builder()
    //             .setOutput(PORT_1)
    //             .build();
    //     PiAction mappedAction = interpreter.mapTreatment(
    //             treatment, P4InfoConstants.FABRIC_INGRESS_NEXT_SIMPLE);
    //     PiActionParam param = new PiActionParam(P4InfoConstants.PORT_NUM, PORT_1.toLong());
    //     PiAction expectedAction = PiAction.builder()
    //             .withId(P4InfoConstants.FABRIC_INGRESS_NEXT_OUTPUT_SIMPLE)
    //             .withParameter(param)
    //             .build();
    //     assertEquals(expectedAction, mappedAction);
    // }

    /**
     * Map treatment for hashed table to routing v4 action.
     */
    @Test
    public void testNextTreatmentHashedRoutingV4() throws Exception {
        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .setEthSrc(SRC_MAC)
                .setEthDst(DST_MAC)
                .setOutput(PORT_1)
                .build();
        PiAction mappedAction = interpreter.mapTreatment(
                treatment, P4InfoConstants.FABRIC_INGRESS_NEXT_HASHED);
        PiActionParam ethSrcParam = new PiActionParam(P4InfoConstants.SMAC, SRC_MAC.toBytes());
        PiActionParam ethDstParam = new PiActionParam(P4InfoConstants.DMAC, DST_MAC.toBytes());
        PiActionParam portParam = new PiActionParam(P4InfoConstants.PORT_NUM, PORT_1.toLong());
        PiAction expectedAction = PiAction.builder()
                .withId(P4InfoConstants.FABRIC_INGRESS_NEXT_ROUTING_HASHED)
                .withParameters(ImmutableList.of(ethSrcParam, ethDstParam, portParam))
                .build();
        assertEquals(expectedAction, mappedAction);
    }

    /**
     * Map treatment to set_vlan_output action.
     */
    @Test
    public void testNextVlanTreatment() throws Exception {
        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .setVlanId(VLAN_100)
                .build();
        PiAction mappedAction = interpreter.mapTreatment(
                treatment, P4InfoConstants.FABRIC_INGRESS_PRE_NEXT_NEXT_VLAN);
        PiActionParam vlanParam = new PiActionParam(
                P4InfoConstants.VLAN_ID, VLAN_100.toShort());
        PiAction expectedAction = PiAction.builder()
                .withId(P4InfoConstants.FABRIC_INGRESS_PRE_NEXT_SET_VLAN)
                .withParameter(vlanParam)
                .build();
        assertEquals(expectedAction, mappedAction);
    }

    /**
     * Map treatment to set_mpls action.
     */
    @Test
    public void testNextMplsTreatment() throws Exception {
        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .setMpls(MPLS_10)
                .build();
        PiAction mappedAction = interpreter.mapTreatment(
                treatment, P4InfoConstants.FABRIC_INGRESS_PRE_NEXT_NEXT_MPLS);
        PiActionParam mplsParam = new PiActionParam(
                P4InfoConstants.LABEL, MPLS_10.toInt());
        PiAction expectedAction = PiAction.builder()
                .withId(P4InfoConstants.FABRIC_INGRESS_PRE_NEXT_SET_MPLS_LABEL)
                .withParameter(mplsParam)
                .build();
        assertEquals(expectedAction, mappedAction);
    }

    @Test
    public void testMapOutboundPacketWithoutForwarding()
            throws PiPipelineInterpreter.PiInterpreterException,
            ImmutableByteSequence.ByteSequenceTrimException {
        PortNumber outputPort = PortNumber.portNumber(1);
        TrafficTreatment outputTreatment = DefaultTrafficTreatment.builder()
                .setOutput(outputPort)
                .build();
        ByteBuffer data = ByteBuffer.allocate(64);
        OutboundPacket outPkt = new DefaultOutboundPacket(DEVICE_ID, outputTreatment, data);
        Collection<PiPacketOperation> result = interpreter.mapOutboundPacket(outPkt);
        assertEquals(result.size(), 1);

        ImmutableList.Builder<PiPacketMetadata> builder = ImmutableList.builder();
        builder.add(PiPacketMetadata.builder()
                .withId(P4InfoConstants.PAD0)
                .withValue(ImmutableByteSequence.copyFrom(0)
                        .fit(P4InfoConstants.PAD0_BITWIDTH))
                .build());
        builder.add(PiPacketMetadata.builder()
                .withId(P4InfoConstants.EGRESS_PORT)
                .withValue(ImmutableByteSequence.copyFrom(outputPort.toLong())
                        .fit(P4InfoConstants.EGRESS_PORT_BITWIDTH))
                .build());
        builder.add(PiPacketMetadata.builder()
                .withId(P4InfoConstants.PAD1)
                .withValue(ImmutableByteSequence.copyFrom(0)
                        .fit(P4InfoConstants.PAD1_BITWIDTH))
                .build());
        builder.add(PiPacketMetadata.builder()
                .withId(P4InfoConstants.QUEUE_ID)
                .withValue(ImmutableByteSequence.copyFrom(SYSTEM_QUEUE_ID)
                        .fit(P4InfoConstants.QUEUE_ID_BITWIDTH))
                .build());
        builder.add(PiPacketMetadata.builder()
                .withId(P4InfoConstants.PAD2)
                .withValue(ImmutableByteSequence.copyFrom(0)
                        .fit(P4InfoConstants.PAD2_BITWIDTH))
                .build());
        builder.add(PiPacketMetadata.builder()
                .withId(P4InfoConstants.CPU_LOOPBACK_MODE)
                .withValue(ImmutableByteSequence.copyFrom(0)
                        .fit(P4InfoConstants.CPU_LOOPBACK_MODE_BITWIDTH))
                .build());
        builder.add(PiPacketMetadata.builder()
                .withId(P4InfoConstants.DO_FORWARDING)
                .withValue(ImmutableByteSequence.copyFrom(0)
                        .fit(P4InfoConstants.DO_FORWARDING_BITWIDTH))
                .build());
        builder.add(PiPacketMetadata.builder()
                .withId(P4InfoConstants.PAD3)
                .withValue(ImmutableByteSequence.copyFrom(0)
                        .fit(P4InfoConstants.PAD3_BITWIDTH))
                .build());
        builder.add(PiPacketMetadata.builder()
                .withId(P4InfoConstants.PAD4)
                .withValue(ImmutableByteSequence.copyFrom(0)
                        .fit(P4InfoConstants.PAD4_BITWIDTH))
                .build());
        builder.add(PiPacketMetadata.builder()
                .withId(P4InfoConstants.ETHER_TYPE)
                .withValue(ImmutableByteSequence.copyFrom(0xBF01)
                        .fit(P4InfoConstants.ETHER_TYPE_BITWIDTH))
                .build());
        PiPacketOperation expectedPktOp = PiPacketOperation.builder()
                .withType(PiPacketOperationType.PACKET_OUT)
                .withData(ImmutableByteSequence.copyFrom(data))
                .withMetadatas(builder.build())
                .build();

        assertEquals(expectedPktOp, result.iterator().next());
    }

    @Test
    public void testMapOutboundPacketWithForwarding()
            throws PiPipelineInterpreter.PiInterpreterException,
            ImmutableByteSequence.ByteSequenceTrimException {
        PortNumber outputPort = PortNumber.TABLE;
        TrafficTreatment outputTreatment = DefaultTrafficTreatment.builder()
                .setOutput(outputPort)
                .build();
        ByteBuffer data = ByteBuffer.allocate(64);
        OutboundPacket outPkt = new DefaultOutboundPacket(DEVICE_ID, outputTreatment, data);
        Collection<PiPacketOperation> result = interpreter.mapOutboundPacket(outPkt);
        assertEquals(result.size(), 1);

        ImmutableList.Builder<PiPacketMetadata> builder = ImmutableList.builder();
        builder.add(PiPacketMetadata.builder()
                .withId(P4InfoConstants.PAD0)
                .withValue(ImmutableByteSequence.copyFrom(0)
                        .fit(P4InfoConstants.PAD0_BITWIDTH))
                .build());
        builder.add(PiPacketMetadata.builder()
                .withId(P4InfoConstants.EGRESS_PORT)
                .withValue(ImmutableByteSequence.copyFrom(0)
                        .fit(P4InfoConstants.EGRESS_PORT_BITWIDTH))
                .build());
        builder.add(PiPacketMetadata.builder()
                .withId(P4InfoConstants.PAD1)
                .withValue(ImmutableByteSequence.copyFrom(0)
                        .fit(P4InfoConstants.PAD1_BITWIDTH))
                .build());
        builder.add(PiPacketMetadata.builder()
                .withId(P4InfoConstants.QUEUE_ID)
                .withValue(ImmutableByteSequence.copyFrom(SYSTEM_QUEUE_ID)
                        .fit(P4InfoConstants.QUEUE_ID_BITWIDTH))
                .build());
        builder.add(PiPacketMetadata.builder()
                .withId(P4InfoConstants.PAD2)
                .withValue(ImmutableByteSequence.copyFrom(0)
                        .fit(P4InfoConstants.PAD2_BITWIDTH))
                .build());
        builder.add(PiPacketMetadata.builder()
                .withId(P4InfoConstants.CPU_LOOPBACK_MODE)
                .withValue(ImmutableByteSequence.copyFrom(0)
                        .fit(P4InfoConstants.CPU_LOOPBACK_MODE_BITWIDTH))
                .build());
        builder.add(PiPacketMetadata.builder()
                .withId(P4InfoConstants.DO_FORWARDING)
                .withValue(ImmutableByteSequence.copyFrom(1)
                        .fit(P4InfoConstants.DO_FORWARDING_BITWIDTH))
                .build());
        builder.add(PiPacketMetadata.builder()
                .withId(P4InfoConstants.PAD3)
                .withValue(ImmutableByteSequence.copyFrom(0)
                        .fit(P4InfoConstants.PAD3_BITWIDTH))
                .build());
        builder.add(PiPacketMetadata.builder()
                .withId(P4InfoConstants.PAD4)
                .withValue(ImmutableByteSequence.copyFrom(0)
                        .fit(P4InfoConstants.PAD4_BITWIDTH))
                .build());
        builder.add(PiPacketMetadata.builder()
                .withId(P4InfoConstants.ETHER_TYPE)
                .withValue(ImmutableByteSequence.copyFrom(0xBF01)
                        .fit(P4InfoConstants.ETHER_TYPE_BITWIDTH))
                .build());
        PiPacketOperation expectedPktOp = PiPacketOperation.builder()
                .withType(PiPacketOperationType.PACKET_OUT)
                .withData(ImmutableByteSequence.copyFrom(data))
                .withMetadatas(builder.build())
                .build();

        assertEquals(expectedPktOp, result.iterator().next());
    }

    @Test
    public void testMapInboundPacket() throws ImmutableByteSequence.ByteSequenceTrimException,
            PiPipelineInterpreter.PiInterpreterException {
        PortNumber inputPort = PortNumber.portNumber(1);
        PiPacketMetadata pktInMetadata = PiPacketMetadata.builder()
                .withId(P4InfoConstants.INGRESS_PORT)
                .withValue(ImmutableByteSequence.copyFrom(inputPort.toLong())
                        .fit(P4InfoConstants.INGRESS_PORT_BITWIDTH))
                .build();
        Ethernet packet = new Ethernet();
        packet.setDestinationMACAddress(SRC_MAC);
        packet.setSourceMACAddress(DST_MAC);
        packet.setEtherType((short) 0xBA00);
        packet.setPayload(new Data());

        PiPacketOperation pktInOp = PiPacketOperation.builder()
                .withMetadata(pktInMetadata)
                .withData(ImmutableByteSequence.copyFrom(packet.serialize()))
                .withType(PiPacketOperationType.PACKET_IN)
                .build();
        InboundPacket result = interpreter.mapInboundPacket(pktInOp, DEVICE_ID);

        ConnectPoint receiveFrom = new ConnectPoint(DEVICE_ID, inputPort);
        InboundPacket expectedInboundPacket
                = new DefaultInboundPacket(receiveFrom, packet, ByteBuffer.wrap(packet.serialize()));

        assertEquals(result.receivedFrom(), expectedInboundPacket.receivedFrom());
        assertEquals(result.parsed(), expectedInboundPacket.parsed());
        assertEquals(result.cookie(), expectedInboundPacket.cookie());

        assertEquals(result.unparsed(), expectedInboundPacket.unparsed());
    }

    @Test
    public void testMapInboundPacketWithShortMetadata() throws ImmutableByteSequence.ByteSequenceTrimException,
            PiPipelineInterpreter.PiInterpreterException {
        PortNumber inputPort = PortNumber.portNumber(1);
        PiPacketMetadata pktInMetadata = PiPacketMetadata.builder()
                .withId(P4InfoConstants.INGRESS_PORT)
                .withValue(ImmutableByteSequence.copyFrom(inputPort.toLong()).fit(8))  // deliberately smaller
                .build();
        Ethernet packet = new Ethernet();
        packet.setDestinationMACAddress(SRC_MAC);
        packet.setSourceMACAddress(DST_MAC);
        packet.setEtherType((short) 0xBA00);
        packet.setPayload(new Data());

        PiPacketOperation pktInOp = PiPacketOperation.builder()
                .withMetadata(pktInMetadata)
                .withData(ImmutableByteSequence.copyFrom(packet.serialize()))
                .withType(PiPacketOperationType.PACKET_IN)
                .build();
        InboundPacket result = interpreter.mapInboundPacket(pktInOp, DEVICE_ID);

        ConnectPoint receiveFrom = new ConnectPoint(DEVICE_ID, inputPort);
        InboundPacket expectedInboundPacket
                = new DefaultInboundPacket(receiveFrom, packet, ByteBuffer.wrap(packet.serialize()));

        assertEquals(result.receivedFrom(), expectedInboundPacket.receivedFrom());
        assertEquals(result.parsed(), expectedInboundPacket.parsed());
        assertEquals(result.cookie(), expectedInboundPacket.cookie());

        assertEquals(result.unparsed(), expectedInboundPacket.unparsed());
    }

    @Test
    public void testMapInboundPacketWithCpuPort() throws ImmutableByteSequence.ByteSequenceTrimException,
            PiPipelineInterpreter.PiInterpreterException {
        PortNumber inputPort = PortNumber.portNumber(Constants.PORT_CPU);
        PiPacketMetadata pktInMetadata = PiPacketMetadata.builder()
                .withId(P4InfoConstants.INGRESS_PORT)
                .withValue(ImmutableByteSequence.copyFrom(inputPort.toLong())
                        .fit(P4InfoConstants.INGRESS_PORT_BITWIDTH))
                .build();
        Ethernet packet = new Ethernet();
        packet.setDestinationMACAddress(SRC_MAC);
        packet.setSourceMACAddress(DST_MAC);
        packet.setEtherType((short) 0xBA00);
        packet.setPayload(new Data());

        PiPacketOperation pktInOp = PiPacketOperation.builder()
                .withMetadata(pktInMetadata)
                .withData(ImmutableByteSequence.copyFrom(packet.serialize()))
                .withType(PiPacketOperationType.PACKET_IN)
                .build();
        InboundPacket result = interpreter.mapInboundPacket(pktInOp, DEVICE_ID);

        ConnectPoint receiveFrom = new ConnectPoint(DEVICE_ID, inputPort);
        InboundPacket expectedInboundPacket
                = new DefaultInboundPacket(receiveFrom, packet, ByteBuffer.wrap(packet.serialize()));

        assertEquals(result.receivedFrom(), expectedInboundPacket.receivedFrom());
        assertEquals(result.parsed(), expectedInboundPacket.parsed());
        assertEquals(result.cookie(), expectedInboundPacket.cookie());

        assertEquals(result.unparsed(), expectedInboundPacket.unparsed());
    }

    @Test
    public void testMapInboundPacketWithPortTranslation() throws ImmutableByteSequence.ByteSequenceTrimException,
            PiPipelineInterpreter.PiInterpreterException {
        PortNumber inputPort = PortNumber.portNumber(1, "ONE");
        ConnectPoint receiveFrom = new ConnectPoint(DEVICE_ID, inputPort);

        Port port = createNiceMock(Port.class);
        expect(port.number()).andReturn(inputPort).anyTimes();
        replay(port);

        expect(deviceService.getPort(receiveFrom)).andReturn(port).anyTimes();
        replay(deviceService);

        PiPacketMetadata pktInMetadata = PiPacketMetadata.builder()
                .withId(P4InfoConstants.INGRESS_PORT)
                .withValue(ImmutableByteSequence.copyFrom(inputPort.toLong())
                        .fit(P4InfoConstants.INGRESS_PORT_BITWIDTH))
                .build();
        Ethernet packet = new Ethernet();
        packet.setDestinationMACAddress(SRC_MAC);
        packet.setSourceMACAddress(DST_MAC);
        packet.setEtherType((short) 0xBA00);
        packet.setPayload(new Data());

        PiPacketOperation pktInOp = PiPacketOperation.builder()
                .withMetadata(pktInMetadata)
                .withData(ImmutableByteSequence.copyFrom(packet.serialize()))
                .withType(PiPacketOperationType.PACKET_IN)
                .build();
        InboundPacket result = interpreter.mapInboundPacket(pktInOp, DEVICE_ID);

        InboundPacket expectedInboundPacket
                = new DefaultInboundPacket(receiveFrom, packet, ByteBuffer.wrap(packet.serialize()));

        assertEquals(result.receivedFrom(), expectedInboundPacket.receivedFrom());
        assertEquals(result.receivedFrom().port().name(), expectedInboundPacket.receivedFrom().port().name());
        assertEquals(result.parsed(), expectedInboundPacket.parsed());
        assertEquals(result.cookie(), expectedInboundPacket.cookie());

        assertEquals(result.unparsed(), expectedInboundPacket.unparsed());
    }
}
