// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
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
import org.onosproject.net.PortNumber;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.packet.DefaultInboundPacket;
import org.onosproject.net.packet.DefaultOutboundPacket;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.pi.model.PiPacketOperationType;
import org.onosproject.net.pi.model.PiPipelineInterpreter;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiActionParam;
import org.onosproject.net.pi.runtime.PiPacketMetadata;
import org.onosproject.net.pi.runtime.PiPacketOperation;

import java.nio.ByteBuffer;
import java.util.Collection;

import static org.easymock.EasyMock.createNiceMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.junit.Assert.assertEquals;
import static org.stratumproject.fabric.tna.behaviour.Constants.*;

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

    private FabricInterpreter interpreter;

    FabricCapabilities allCapabilities;

    @Before
    public void setup() {
        allCapabilities = createNiceMock(FabricCapabilities.class);
        expect(allCapabilities.hasHashedTable()).andReturn(true).anyTimes();
        expect(allCapabilities.supportDoubleVlanTerm()).andReturn(true).anyTimes();
        replay(allCapabilities);
        interpreter = new FabricInterpreter(allCapabilities);
    }

    /* Filtering control block */

    /**
     * Map treatment to push_internal_vlan action.
     */
    @Test
    public void testFilteringTreatmentPermitWithInternalVlan() throws Exception {
        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .pushVlan()
                .setVlanId(VLAN_100)
                .build();
        PiAction mappedAction = interpreter.mapTreatment(treatment,
                P4InfoConstants.FABRIC_INGRESS_FILTERING_INGRESS_PORT_VLAN);
        PiActionParam param1 = new PiActionParam(P4InfoConstants.VLAN_ID,
                ImmutableByteSequence.copyFrom(VLAN_100.toShort()));
        PiActionParam param2 = new PiActionParam(P4InfoConstants.PORT_TYPE, EDGE);
        PiAction expectedAction = PiAction.builder()
                .withId(P4InfoConstants.FABRIC_INGRESS_FILTERING_PERMIT_WITH_INTERNAL_VLAN)
                .withParameter(param1)
                .withParameter(param2)
                .build();

        assertEquals(expectedAction, mappedAction);

        treatment = DefaultTrafficTreatment.builder()
                .pushVlan()
                .setVlanId(VlanId.vlanId((short) DEFAULT_VLAN))
                .writeMetadata(IS_INFRA_PORT, METADATA_MASK)
                .build();
        mappedAction = interpreter.mapTreatment(treatment,
                P4InfoConstants.FABRIC_INGRESS_FILTERING_INGRESS_PORT_VLAN);
        param1 = new PiActionParam(P4InfoConstants.VLAN_ID,
                ImmutableByteSequence.copyFrom((short) DEFAULT_VLAN));
        param2 = new PiActionParam(P4InfoConstants.PORT_TYPE, INFRA);
        expectedAction = PiAction.builder()
                .withId(P4InfoConstants.FABRIC_INGRESS_FILTERING_PERMIT_WITH_INTERNAL_VLAN)
                .withParameter(param1)
                .withParameter(param2)
                .build();

        assertEquals(expectedAction, mappedAction);
    }

    /**
     * Map treatment to permit action.
     */
    @Test
    public void testFilteringTreatmentPermit() throws Exception {
        TrafficTreatment treatment = DefaultTrafficTreatment.emptyTreatment();
        PiAction mappedAction = interpreter.mapTreatment(treatment,
                P4InfoConstants.FABRIC_INGRESS_FILTERING_INGRESS_PORT_VLAN);
        PiActionParam param = new PiActionParam(P4InfoConstants.PORT_TYPE, EDGE);
        PiAction expectedAction = PiAction.builder()
                .withId(P4InfoConstants.FABRIC_INGRESS_FILTERING_PERMIT)
                .withParameter(param)
                .build();

        assertEquals(expectedAction, mappedAction);

        treatment = DefaultTrafficTreatment.builder()
                .writeMetadata(IS_INFRA_PORT, METADATA_MASK)
                .build();
        mappedAction = interpreter.mapTreatment(treatment,
                P4InfoConstants.FABRIC_INGRESS_FILTERING_INGRESS_PORT_VLAN);
        param = new PiActionParam(P4InfoConstants.PORT_TYPE, INFRA);
        expectedAction = PiAction.builder()
                .withId(P4InfoConstants.FABRIC_INGRESS_FILTERING_PERMIT)
                .withParameter(param)
                .build();

        assertEquals(expectedAction, mappedAction);
    }

    /* Forwarding control block */

    /**
     * Map empty treatment for routing v4 table.
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
     * Map empty treatment for ACL table.
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
    public void testMapOutboundPacket() throws PiPipelineInterpreter.PiInterpreterException,
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
                .withId(P4InfoConstants.EGRESS_PORT)
                .withValue(ImmutableByteSequence.copyFrom(outputPort.toLong())
                        .fit(P4InfoConstants.EGRESS_PORT_BITWIDTH))
                .build());
        builder.add(PiPacketMetadata.builder()
                .withId(P4InfoConstants.CPU_LOOPBACK_MODE)
                .withValue(ImmutableByteSequence.copyFrom(0)
                        .fit(P4InfoConstants.CPU_LOOPBACK_MODE_BITWIDTH))
                .build());
        builder.add(PiPacketMetadata.builder()
                .withId(P4InfoConstants.ETHER_TYPE)
                .withValue(ImmutableByteSequence.copyFrom(0xBF01)
                        .fit(P4InfoConstants.ETHER_TYPE_BITWIDTH))
                .build());
        builder.add(PiPacketMetadata.builder()
                .withId(P4InfoConstants.PAD0)
                .withValue(ImmutableByteSequence.copyFrom(0)
                        .fit(P4InfoConstants.PAD0_BITWIDTH))
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
                .withValue(ImmutableByteSequence.copyFrom(inputPort.toLong()).fit(9))
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
}
