// Copyright 2017-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package org.stratumproject.fabric.tna.behaviour;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import org.onlab.packet.DeserializationException;
import org.onlab.packet.Ethernet;
import org.onlab.util.ImmutableByteSequence;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Port;
import org.onosproject.net.PortNumber;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.driver.DriverHandler;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flow.instructions.Instructions;
import org.onosproject.net.packet.DefaultInboundPacket;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.pi.model.PiMatchFieldId;
import org.onosproject.net.pi.model.PiPipelineInterpreter;
import org.onosproject.net.pi.model.PiTableId;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiPacketMetadata;
import org.onosproject.net.pi.runtime.PiPacketOperation;

import java.nio.ByteBuffer;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static java.lang.String.format;
import static java.util.stream.Collectors.toList;
import static org.onlab.util.ImmutableByteSequence.copyFrom;
import static org.onosproject.net.PortNumber.CONTROLLER;
import static org.onosproject.net.PortNumber.FLOOD;
import static org.onosproject.net.PortNumber.TABLE;
import static org.onosproject.net.flow.instructions.Instruction.Type.OUTPUT;
import static org.onosproject.net.pi.model.PiPacketOperationType.PACKET_OUT;
import static org.stratumproject.fabric.tna.behaviour.Constants.ONE;
import static org.stratumproject.fabric.tna.behaviour.Constants.QUEUE_ID_SYSTEM;
import static org.stratumproject.fabric.tna.behaviour.Constants.ZERO;
import static org.stratumproject.fabric.tna.behaviour.FabricTreatmentInterpreter.mapAclTreatment;
import static org.stratumproject.fabric.tna.behaviour.FabricTreatmentInterpreter.mapEgressNextTreatment;
import static org.stratumproject.fabric.tna.behaviour.FabricTreatmentInterpreter.mapForwardingTreatment;
import static org.stratumproject.fabric.tna.behaviour.FabricTreatmentInterpreter.mapNextTreatment;
import static org.stratumproject.fabric.tna.behaviour.FabricTreatmentInterpreter.mapPreNextTreatment;

/**
 * Interpreter for fabric-tna pipeline.
 */
public class FabricInterpreter extends AbstractFabricHandlerBehavior
        implements PiPipelineInterpreter {

    private static final int CPU_LOOPBACK_MODE_DISABLED = 0;
    private static final int CPU_LOOPBACK_MODE_DIRECT = 1;
    private static final int CPU_LOOPBACK_MODE_INGRESS = 2;
    private static final int ETHER_TYPE_PACKET_OUT = 0xBF01;

    // Group tables by control block.
    private static final Set<PiTableId> FORWARDING_CTRL_TBLS = ImmutableSet.of(
            P4InfoConstants.FABRIC_INGRESS_FORWARDING_MPLS,
            P4InfoConstants.FABRIC_INGRESS_FORWARDING_ROUTING_V4,
            P4InfoConstants.FABRIC_INGRESS_FORWARDING_ROUTING_V6,
            P4InfoConstants.FABRIC_INGRESS_FORWARDING_BRIDGING);
    private static final Set<PiTableId> PRE_NEXT_CTRL_TBLS = ImmutableSet.of(
            P4InfoConstants.FABRIC_INGRESS_PRE_NEXT_NEXT_MPLS,
            P4InfoConstants.FABRIC_INGRESS_PRE_NEXT_NEXT_VLAN);
    private static final Set<PiTableId> ACL_CTRL_TBLS = ImmutableSet.of(
            P4InfoConstants.FABRIC_INGRESS_ACL_ACL);
    private static final Set<PiTableId> NEXT_CTRL_TBLS = ImmutableSet.of(
            // TODO: add profile with simple next or remove references
            // P4InfoConstants.FABRIC_INGRESS_NEXT_SIMPLE,
            // TODO: re-enable support for xconnext
            // P4InfoConstants.FABRIC_INGRESS_NEXT_XCONNECT,
            P4InfoConstants.FABRIC_INGRESS_NEXT_HASHED);
    private static final Set<PiTableId> E_NEXT_CTRL_TBLS = ImmutableSet.of(
            P4InfoConstants.FABRIC_EGRESS_EGRESS_NEXT_EGRESS_VLAN);

    private static final ImmutableMap<Criterion.Type, PiMatchFieldId> CRITERION_MAP =
            ImmutableMap.<Criterion.Type, PiMatchFieldId>builder()
                    .put(Criterion.Type.IN_PORT, P4InfoConstants.HDR_IG_PORT)
                    .put(Criterion.Type.ETH_DST, P4InfoConstants.HDR_ETH_DST)
                    .put(Criterion.Type.ETH_SRC, P4InfoConstants.HDR_ETH_SRC)
                    .put(Criterion.Type.ETH_DST_MASKED, P4InfoConstants.HDR_ETH_DST)
                    .put(Criterion.Type.ETH_SRC_MASKED, P4InfoConstants.HDR_ETH_SRC)
                    .put(Criterion.Type.ETH_TYPE, P4InfoConstants.HDR_ETH_TYPE)
                    .put(Criterion.Type.MPLS_LABEL, P4InfoConstants.HDR_MPLS_LABEL)
                    .put(Criterion.Type.VLAN_VID, P4InfoConstants.HDR_VLAN_ID)
                    // TODO: re-enable support for double-vlan
                    // .put(Criterion.Type.INNER_VLAN_VID, P4InfoConstants.HDR_INNER_VLAN_ID)
                    .put(Criterion.Type.IPV4_DST, P4InfoConstants.HDR_IPV4_DST)
                    .put(Criterion.Type.IPV4_SRC, P4InfoConstants.HDR_IPV4_SRC)
                    .put(Criterion.Type.IPV6_DST, P4InfoConstants.HDR_IPV6_DST)
                    .put(Criterion.Type.IP_PROTO, P4InfoConstants.HDR_IP_PROTO)
                    .put(Criterion.Type.ICMPV6_TYPE, P4InfoConstants.HDR_ICMP_TYPE)
                    .put(Criterion.Type.ICMPV6_CODE, P4InfoConstants.HDR_ICMP_CODE)
                    .put(Criterion.Type.UDP_DST, P4InfoConstants.HDR_L4_DPORT)
                    .put(Criterion.Type.UDP_SRC, P4InfoConstants.HDR_L4_SPORT)
                    .put(Criterion.Type.UDP_DST_MASKED, P4InfoConstants.HDR_L4_DPORT)
                    .put(Criterion.Type.UDP_SRC_MASKED, P4InfoConstants.HDR_L4_SPORT)
                    .put(Criterion.Type.TCP_DST, P4InfoConstants.HDR_L4_DPORT)
                    .put(Criterion.Type.TCP_SRC, P4InfoConstants.HDR_L4_SPORT)
                    .put(Criterion.Type.TCP_DST_MASKED, P4InfoConstants.HDR_L4_DPORT)
                    .put(Criterion.Type.TCP_SRC_MASKED, P4InfoConstants.HDR_L4_SPORT)
                    .build();

    private static final PiAction NOP = PiAction.builder()
            .withId(P4InfoConstants.NOP).build();

    private static final ImmutableMap<PiTableId, PiAction> DEFAULT_ACTIONS =
            ImmutableMap.<PiTableId, PiAction>builder()
                    .put(P4InfoConstants.FABRIC_INGRESS_FORWARDING_ROUTING_V4, NOP)
                    .build();

    private FabricTreatmentInterpreter treatmentInterpreter;

    /**
     * Creates a new instance of this behavior with the given capabilities.
     *
     * @param capabilities capabilities
     */
    public FabricInterpreter(FabricCapabilities capabilities) {
        super(capabilities);
        instantiateTreatmentInterpreter();
    }

    /**
     * Create a new instance of this behaviour. Used by the abstract projectable
     * model (i.e., {@link org.onosproject.net.Device#as(Class)}.
     */
    public FabricInterpreter() {
        super();
    }

    private void instantiateTreatmentInterpreter() {
        this.treatmentInterpreter = new FabricTreatmentInterpreter(this.capabilities);
    }

    @Override
    public void setHandler(DriverHandler handler) {
        super.setHandler(handler);
        instantiateTreatmentInterpreter();
    }

    @Override
    public Optional<PiMatchFieldId> mapCriterionType(Criterion.Type type) {
        return Optional.ofNullable(CRITERION_MAP.get(type));
    }

    @Override
    public Optional<PiTableId> mapFlowRuleTableId(int flowRuleTableId) {
        // The only use case for Index ID->PiTableId is when using the single
        // table pipeliner. fabric.p4 is never used with such pipeliner.
        return Optional.empty();
    }

    @Override
    public PiAction mapTreatment(TrafficTreatment treatment, PiTableId piTableId)
            throws PiInterpreterException {
        if (FORWARDING_CTRL_TBLS.contains(piTableId)) {
            return mapForwardingTreatment(treatment, piTableId);
        } else if (PRE_NEXT_CTRL_TBLS.contains(piTableId)) {
            return mapPreNextTreatment(treatment, piTableId);
        } else if (ACL_CTRL_TBLS.contains(piTableId)) {
            return mapAclTreatment(treatment, piTableId);
        } else if (NEXT_CTRL_TBLS.contains(piTableId)) {
            return mapNextTreatment(treatment, piTableId);
        } else if (E_NEXT_CTRL_TBLS.contains(piTableId)) {
            return mapEgressNextTreatment(treatment, piTableId);
        } else {
            throw new PiInterpreterException(format(
                    "Treatment mapping not supported for table '%s'", piTableId));
        }
    }

    private PiPacketOperation createPiPacketOperation(
            ByteBuffer data, long portNumber, boolean doForwarding)
            throws PiInterpreterException {
        Collection<PiPacketMetadata> metadata = createPacketMetadata(portNumber, doForwarding);
        return PiPacketOperation.builder()
                .withType(PACKET_OUT)
                .withData(copyFrom(data))
                .withMetadatas(metadata)
                .build();
    }

    private Collection<PiPacketMetadata> createPacketMetadata(
            long portNumber, boolean doForwarding)
            throws PiInterpreterException {
        try {
            ImmutableList.Builder<PiPacketMetadata> builder = ImmutableList.builder();
            builder.add(PiPacketMetadata.builder()
                    .withId(P4InfoConstants.PAD0)
                    .withValue(copyFrom(0)
                            .fit(P4InfoConstants.PAD0_BITWIDTH))
                    .build());
            builder.add(PiPacketMetadata.builder()
                    .withId(P4InfoConstants.EGRESS_PORT)
                    .withValue(copyFrom(portNumber)
                            .fit(P4InfoConstants.EGRESS_PORT_BITWIDTH))
                    .build());
            builder.add(PiPacketMetadata.builder()
                    .withId(P4InfoConstants.PAD1)
                    .withValue(copyFrom(0)
                            .fit(P4InfoConstants.PAD1_BITWIDTH))
                    .build());
            builder.add(PiPacketMetadata.builder()
                    .withId(P4InfoConstants.QUEUE_ID)
                    .withValue(copyFrom(QUEUE_ID_SYSTEM)
                            .fit(P4InfoConstants.QUEUE_ID_BITWIDTH))
                    .build());
            builder.add(PiPacketMetadata.builder()
                    .withId(P4InfoConstants.PAD2)
                    .withValue(copyFrom(0)
                            .fit(P4InfoConstants.PAD2_BITWIDTH))
                    .build());
            builder.add(PiPacketMetadata.builder()
                    .withId(P4InfoConstants.CPU_LOOPBACK_MODE)
                    .withValue(copyFrom(CPU_LOOPBACK_MODE_DISABLED)
                            .fit(P4InfoConstants.CPU_LOOPBACK_MODE_BITWIDTH))
                    .build());
            builder.add(PiPacketMetadata.builder()
                    .withId(P4InfoConstants.DO_FORWARDING)
                    .withValue(copyFrom(doForwarding ? ONE : ZERO))
                    .build());
            builder.add(PiPacketMetadata.builder()
                    .withId(P4InfoConstants.PAD3)
                    .withValue(copyFrom(0)
                            .fit(P4InfoConstants.PAD3_BITWIDTH))
                    .build());
            builder.add(PiPacketMetadata.builder()
                    .withId(P4InfoConstants.PAD4)
                    .withValue(copyFrom(0)
                            .fit(P4InfoConstants.PAD4_BITWIDTH))
                    .build());
            builder.add(PiPacketMetadata.builder()
                    .withId(P4InfoConstants.ETHER_TYPE)
                    .withValue(copyFrom(ETHER_TYPE_PACKET_OUT)
                            .fit(P4InfoConstants.ETHER_TYPE_BITWIDTH))
                    .build());
            return builder.build();
        } catch (ImmutableByteSequence.ByteSequenceTrimException e) {
            throw new PiInterpreterException(format(
                    "Port number '%d' too big, %s", portNumber, e.getMessage()));
        }
    }

    @Override
    public Collection<PiPacketOperation> mapOutboundPacket(OutboundPacket packet)
            throws PiInterpreterException {
        TrafficTreatment treatment = packet.treatment();

        // We support only OUTPUT instructions.
        List<Instructions.OutputInstruction> outInstructions = treatment
                .allInstructions()
                .stream()
                .filter(i -> i.type().equals(OUTPUT))
                .map(i -> (Instructions.OutputInstruction) i)
                .collect(toList());

        if (treatment.allInstructions().size() != outInstructions.size()) {
            // There are other instructions that are not of type OUTPUT.
            throw new PiInterpreterException("Treatment not supported: " + treatment);
        }

        ImmutableList.Builder<PiPacketOperation> builder = ImmutableList.builder();
        for (Instructions.OutputInstruction outInst : outInstructions) {
            if (outInst.port().equals(TABLE)) {
                // Logical port. Forward using the switch tables like a regular packet.
                builder.add(createPiPacketOperation(packet.data(), 0, true));
            } else if (outInst.port().equals(FLOOD)) {
                // Logical port. Create a packet operation for each switch port.
                final DeviceService deviceService = handler().get(DeviceService.class);
                for (Port port : deviceService.getPorts(packet.sendThrough())) {
                    builder.add(createPiPacketOperation(packet.data(), port.number().toLong(), false));
                }
            } else if (outInst.port().isLogical()) {
                throw new PiInterpreterException(format(
                        "Output on logical port '%s' not supported", outInst.port()));
            } else {
                // Send as-is to given port bypassing all switch tables.
                builder.add(createPiPacketOperation(packet.data(), outInst.port().toLong(), false));
            }
        }
        return builder.build();
    }

    @Override
    public InboundPacket mapInboundPacket(PiPacketOperation packetIn, DeviceId deviceId) throws PiInterpreterException {
        // Assuming that the packet is ethernet, which is fine since fabric.p4
        // can deparse only ethernet packets.
        Ethernet ethPkt;
        try {
            ethPkt = Ethernet.deserializer().deserialize(packetIn.data().asArray(), 0,
                                                         packetIn.data().size());
        } catch (DeserializationException dex) {
            throw new PiInterpreterException(dex.getMessage());
        }

        // Returns the ingress port packet metadata.
        Optional<PiPacketMetadata> packetMetadata = packetIn.metadatas()
                .stream().filter(m -> m.id().equals(P4InfoConstants.INGRESS_PORT))
                .findFirst();

        if (packetMetadata.isPresent()) {
            try {
                ImmutableByteSequence portByteSequence = packetMetadata.get()
                        .value().fit(P4InfoConstants.INGRESS_PORT_BITWIDTH);
                short s = portByteSequence.asReadOnlyBuffer().getShort();
                ConnectPoint receivedFrom = new ConnectPoint(deviceId, PortNumber.portNumber(s));
                if (!receivedFrom.port().hasName()) {
                    receivedFrom = translateSwitchPort(receivedFrom);
                }
                ByteBuffer rawData = ByteBuffer.wrap(packetIn.data().asArray());
                return new DefaultInboundPacket(receivedFrom, ethPkt, rawData);
            } catch (ImmutableByteSequence.ByteSequenceTrimException e) {
                throw new PiInterpreterException(format(
                        "Malformed metadata '%s' in packet-in received from '%s': %s",
                        P4InfoConstants.INGRESS_PORT, deviceId, packetIn));
            }
        } else {
            throw new PiInterpreterException(format(
                    "Missing metadata '%s' in packet-in received from '%s': %s",
                    P4InfoConstants.INGRESS_PORT, deviceId, packetIn));
        }
    }

    @Override
    public Optional<PiAction> getOriginalDefaultAction(PiTableId tableId) {
        return Optional.ofNullable(DEFAULT_ACTIONS.get(tableId));
    }

    @Override
    public Optional<Integer> mapLogicalPortNumber(PortNumber port) {
        if (!port.equals(CONTROLLER)) {
            return Optional.empty();
        }
        return capabilities.cpuPort();
    }

    /* Connect point generated using sb metadata does not have port name
       we use the device service as translation service */
    private ConnectPoint translateSwitchPort(ConnectPoint connectPoint) {
        final DeviceService deviceService = handler().get(DeviceService.class);
        if (deviceService == null) {
            log.warn("Unable to translate switch port due to DeviceService not available");
            return connectPoint;
        }
        Port devicePort = deviceService.getPort(connectPoint);
        if (devicePort != null) {
            return new ConnectPoint(connectPoint.deviceId(), devicePort.number());
        }
        return connectPoint;
    }
}
