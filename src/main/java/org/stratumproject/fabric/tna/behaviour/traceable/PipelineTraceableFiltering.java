// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package org.stratumproject.fabric.tna.behaviour.traceable;

import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import org.onlab.packet.EthType;
import org.onlab.packet.Ethernet;
import org.onlab.packet.MacAddress;
import org.onlab.packet.VlanId;
import org.onlab.util.ImmutableByteSequence;
import org.onosproject.net.DataPlaneEntity;
import org.onosproject.net.PipelineTraceableHitChain;
import org.onosproject.net.PipelineTraceableInput;
import org.onosproject.net.PipelineTraceableOutput;
import org.onosproject.net.PipelineTraceablePacket;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.FlowEntry;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flow.criteria.EthCriterion;
import org.onosproject.net.flow.criteria.EthTypeCriterion;
import org.onosproject.net.flow.criteria.MetadataCriterion;
import org.onosproject.net.flow.criteria.PiCriterion;
import org.onosproject.net.flow.criteria.PortCriterion;
import org.onosproject.net.flow.criteria.VlanIdCriterion;
import org.onosproject.net.pi.model.PiPipeconf;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiActionParam;
import org.onosproject.net.pi.runtime.PiFieldMatch;
import org.onosproject.net.pi.runtime.PiTableAction;
import org.onosproject.net.pi.runtime.PiTableEntry;
import org.onosproject.net.pi.service.PiTranslationException;
import org.onosproject.net.pi.service.PiTranslationService;
import org.stratumproject.fabric.tna.behaviour.FabricCapabilities;
import org.stratumproject.fabric.tna.behaviour.P4InfoConstants;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.stratumproject.fabric.tna.behaviour.FabricUtils.criterion;

/**
 * Implementation of the filtering control block for fabric-tna.
 */
class PipelineTraceableFiltering extends AbstractPipelineTraceableCtrl {

    // For the filtering selector utils
    private static final byte[] ONE = new byte[]{1};
    private static final byte[] ZERO = new byte[]{0};
    private static final short ETH_TYPE_EXACT_MASK = (short) 0xFFFF;

    /**
     * Creates a new instance of a control block with the given capabilities
     * and pipeconf.
     *
     * @param capabilities capabilities
     * @param pipeconf pipeconf
     * @param piTranslationService pi translation service
     */
    public PipelineTraceableFiltering(FabricCapabilities capabilities, PiPipeconf pipeconf,
                                      PiTranslationService piTranslationService) {
       super(capabilities, pipeconf, piTranslationService, DataPlaneEntity.Type.FLOWRULE);
       // Initialize table ids
       this.tableIds = Lists.newArrayList(
               P4InfoConstants.FABRIC_INGRESS_FILTERING_INGRESS_PORT_VLAN,
               P4InfoConstants.FABRIC_INGRESS_FILTERING_FWD_CLASSIFIER
       );
    }

    @Override
    // Apply the traceable control logic
    public PipelineTraceableOutput apply(PipelineTraceableInput input) {
        // Init steps.
        FabricTraceableMetadata.Builder metadataBuilder = getMetadata(input.ingressPacket());
        TrafficSelector packet = input.ingressPacket().packet();
        PipelineTraceableOutput.Builder outputBuilder = PipelineTraceableOutput.builder();
        PipelineTraceableHitChain currentHitChain = PipelineTraceableHitChain.emptyHitChain();
        PipelineTraceablePacket egressPacket = new PipelineTraceablePacket(
                input.ingressPacket().packet(), metadataBuilder.build());

        // Gets the related flows - if there are no flows exit.
        List<DataPlaneEntity> filteringFlows = getDataPlaneEntity(input.deviceState());
        if (filteringFlows.isEmpty()) {
            currentHitChain.setEgressPacket(egressPacket);
            currentHitChain.dropped();
            return outputBuilder.appendToLog("There are no flows for " + getClass().getSimpleName() +
                    ". Aborting")
                    .noFlows()
                    .addHitChain(currentHitChain)
                    .build();
        }

        // Gets the matching table entries
        List<PiTableEntry> matchedTableEntries = Lists.newArrayList();
        PiTableEntry bestTer = null;
        Map<PiTableEntry, DataPlaneEntity> mapping = Maps.newHashMap();
        for (DataPlaneEntity dataPlaneEntity : filteringFlows) {

            if (log.isDebugEnabled()) {
                log.debug("Packet before filtering augmentation {}", packet);
            }
            // Before the conversion to flowrule augment the packet with the hidden fields
            TrafficSelector packetForPiTranslation = augmentPacket(packet, null, dataPlaneEntity);
            // We cannot proceed if the augmentation failed. Selector should contain at least the pi criterion
            if (packetForPiTranslation.equals(DefaultTrafficSelector.emptySelector())) {
                log.debug("matchFilteringTables failed due to augmentation error");
                continue;
            }
            if (log.isDebugEnabled()) {
                log.debug("Packet after filtering augmentation {}", packetForPiTranslation);
            }

            PiTableEntry tableEntry = matchTables(packetForPiTranslation, dataPlaneEntity);
            if (tableEntry != null) {
                // FWD Classifier rules may have conflicts - we need to select them
                // based on the priority of the pi table entries
                if (tableEntry.table().equals(P4InfoConstants.FABRIC_INGRESS_FILTERING_FWD_CLASSIFIER)) {
                    bestTer = TraceableUtils.selectBestTerEntry(bestTer, tableEntry);
                    mapping.put(tableEntry, dataPlaneEntity);
                } else {
                    matchedTableEntries.add(tableEntry);
                    currentHitChain.addDataPlaneEntity(dataPlaneEntity);
                }
            }
        }

        // If there was a match, let's add them to the matched entries.
        // We use the mapping to retrieve the dataplane entity
        if (bestTer != null) {
            matchedTableEntries.add(bestTer);
            currentHitChain.addDataPlaneEntity(mapping.get(bestTer));
        }

        // Table miss scenarios for port vlan
        if (portVlanTableMiss(matchedTableEntries)) {
            // Apply deny() as default action
            metadataBuilder.setSkipFwd()
                    .setSkipNext();
        }

        // Table miss scenarios for fwd classifier
        if (fwdClassifierTableMiss(matchedTableEntries)) {
            // Set BRIDGING as default action
            metadataBuilder.setBridgingFwdType();
        }

        // Apply the matched flow rule
        matchedTableEntries.forEach(matchedTableEntry -> applyTables(metadataBuilder, matchedTableEntry));

        // Finally build the output that will be used as input for the next block
        egressPacket = new PipelineTraceablePacket(
                input.ingressPacket().packet(), metadataBuilder.build());
        currentHitChain.setEgressPacket(egressPacket);
        currentHitChain.pass();
        return outputBuilder.addHitChain(currentHitChain)
                .build();
    }

    @Override
    public PiTableEntry matchTables(TrafficSelector packetForPiTranslation, DataPlaneEntity dataPlaneEntity) {
        // Convert the packet in a flowrule using the treatment of the
        // flowentry we are currently analyzing
        FlowEntry flowEntry = dataPlaneEntity.getFlowEntry();
        FlowRule packetFlow = createFlowForPiTranslation(flowEntry, packetForPiTranslation)
                .build();

        // Translate the packet and the flow entry in pi table entries and verify the matching
        try {
            PiTableEntry packetTranslated =
                    piTranslationService.flowRuleTranslator().translate(packetFlow, pipeconf);
            PiTableEntry matchFlowTranslated =
                    piTranslationService.flowRuleTranslator().translate(flowEntry, pipeconf);
            // FIXME support Multicast (mac in range)
            return matchFlowTranslated.matchKey().fieldMatches().stream()
                    // Note this is a simplification:
                    // We can potentially use ternaryMatch() implementation
                    .allMatch(fieldMatch -> packetTranslated.matchKey().fieldMatches().contains(fieldMatch)) ?
                    matchFlowTranslated : null;
        } catch (PiTranslationException e) {
            log.debug("matchFilteringTables failed due to PI translation error: {}", e.getMessage());
        }
        return null;
    }

    @Override
    public TrafficSelector augmentPacket(TrafficSelector packet, FabricTraceableMetadata metadata,
                                         DataPlaneEntity dataPlaneEntity) {
        // Prepare the packet for the translation introducing the hidden fields added by the pipeliner.
        FlowEntry flowEntry = dataPlaneEntity.getFlowEntry();
        TrafficSelector.Builder packetForPiTranslation = DefaultTrafficSelector.builder();
        PiCriterion.Builder piCriterionForTranslation = PiCriterion.builder();
        // Augmentation step is in somewhat close to the parsing. It introduces hidden fields
        // added by the pipeliner. These fields are stored inside a pi criterion. This step is mandatory
        // for the proper translation of the traffic selector.
        if (flowEntry.table().equals(P4InfoConstants.FABRIC_INGRESS_FILTERING_INGRESS_PORT_VLAN)) {
            // Adds PORT_VLAN table hidden fields
            if (log.isDebugEnabled()) {
                log.debug("Augments packet with port vlan selector");
            }
            TrafficSelector portVlanSelector = getPortVlanMatchFields(packet, piCriterionForTranslation);
            portVlanSelector.criteria().forEach(packetForPiTranslation::add);
        } else if (flowEntry.table().equals(P4InfoConstants.FABRIC_INGRESS_FILTERING_FWD_CLASSIFIER)) {
            // Adds FWD_CLASS table hidden fields
            if (log.isDebugEnabled()) {
                log.debug("Augments packet with fwd classifier selector");
            }
            TrafficSelector fwdClassifierSelector = getFwdClassifierFields(packet, piCriterionForTranslation);
            fwdClassifierSelector.criteria().forEach(packetForPiTranslation::add);
        } else {
            return packetForPiTranslation.build();
        }

        // FIXME should we add method to check if the PiCriterion has no match keys
        try {
            PiCriterion piCriterion = piCriterionForTranslation.build();
            // Finally builds up the pi criterion and add to the selector before terminating
            return packetForPiTranslation.matchPi(piCriterion)
                    .build();
        } catch (IllegalArgumentException e) {
            log.debug("PiCriterion is empty");
        }
        return packetForPiTranslation.build();
    }

    @Override
    public void applyTables(FabricTraceableMetadata.Builder metadataBuilder, PiTableEntry piTableEntry) {
        // Apply the given flow entry on the metadata
        if (piTableEntry.action().type() == PiTableAction.Type.ACTION) {
            PiAction piAction = (PiAction) piTableEntry.action();
            if (piAction.id().equals(P4InfoConstants.FABRIC_INGRESS_FILTERING_DENY)) {
                if (log.isDebugEnabled()) {
                    log.debug("applyFilteringTables action DENY");
                }
                // Apply deny action
                metadataBuilder.setSkipFwd()
                        .setSkipNext();
            } else if (piAction.id().equals(P4InfoConstants.FABRIC_INGRESS_FILTERING_PERMIT)) {
                // Permit do nothing
                if (log.isDebugEnabled()) {
                    log.debug("applyFilteringTables action PERMIT");
                }
            } else if (piAction.id().equals(P4InfoConstants.FABRIC_INGRESS_FILTERING_PERMIT_WITH_INTERNAL_VLAN)) {
                if (log.isDebugEnabled()) {
                    log.debug("applyFilteringTables action PERMIT_WITH_VLAN {}", piAction.parameters());
                }
                // Permit with the internal vlan. Default set to NONE
                short vlanId = piAction.parameters()
                        .stream()
                        .findFirst()
                        .orElse(new PiActionParam(P4InfoConstants.VLAN_ID,
                                VlanId.NONE.toShort()))
                        .value()
                        .asReadOnlyBuffer()
                        .getShort();
                metadataBuilder.setVlanId(vlanId);
            } else if (piAction.id().equals(P4InfoConstants.FABRIC_INGRESS_FILTERING_SET_FORWARDING_TYPE)) {
                if (log.isDebugEnabled()) {
                    log.debug("applyFilteringTables action SET FWD TYPE {}", piAction.parameters());
                }
                // Set fwd type. Default set to BRIDGING
                byte fwdType = piAction.parameters()
                        .stream()
                        .findFirst()
                        .orElse(new PiActionParam(P4InfoConstants.FWD_TYPE,
                                ImmutableByteSequence.copyFrom(0)))
                        .value()
                        .asArray()[0];
                metadataBuilder.setFwdType(fwdType);
            } else {
                log.warn("applyFilteringTables does not support action: {}", piAction);
            }
        } else {
            log.warn("applyFilteringTables does not support actions different from : {}",
                    PiAction.Type.ACTION);
        }
    }

    // Returns the traffic selector builder with the standard criterions
    // and updates the pi criterion builder
    private TrafficSelector getPortVlanMatchFields(TrafficSelector packet,
                                                   PiCriterion.Builder piCriterionBuilder) {
        // Starts with the port vlan table hidden fields.
        final PortCriterion inPortCriterion = (PortCriterion) criterion(
                packet.criteria(), Criterion.Type.IN_PORT);
        final VlanIdCriterion outerVlanCriterion = (VlanIdCriterion) criterion(
                packet.criteria(), Criterion.Type.VLAN_VID);
        final VlanIdCriterion innerVlanCriterion = (VlanIdCriterion) criterion(
                packet.criteria(), Criterion.Type.INNER_VLAN_VID);
        final PiCriterion piCriterion = (PiCriterion) criterion(
                packet.criteria(), Criterion.Type.PROTOCOL_INDEPENDENT);

        // We will add the standard criterions only if present
        final boolean outerVlanValid = outerVlanCriterion != null
                && !outerVlanCriterion.vlanId().equals(VlanId.NONE);
        final boolean innerVlanValid = innerVlanCriterion != null
                && !innerVlanCriterion.vlanId().equals(VlanId.NONE);

        // Get the pi criterion and verify if "vlan_is_valid" is already present
        if (piCriterion != null) {
            piCriterion.fieldMatches().forEach(piCriterionBuilder::add);
            Optional<PiFieldMatch> piFieldMatch = piCriterion.fieldMatch(P4InfoConstants.HDR_VLAN_IS_VALID);
            if (!piFieldMatch.isPresent()) {
                piCriterionBuilder.matchExact(P4InfoConstants.HDR_VLAN_IS_VALID,
                        outerVlanValid ? ONE : ZERO);
            }
        } else {
            // There is no pi criterion in the original packet
            piCriterionBuilder.matchExact(P4InfoConstants.HDR_VLAN_IS_VALID,
                    outerVlanValid ? ONE : ZERO);
        }

        // Adds the remaining criterions: inport, outer and inner vlans
        final TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        if (inPortCriterion != null) {
            selector.add(inPortCriterion);
        }
        if (outerVlanValid) {
            selector.add(outerVlanCriterion);
        }
        if (innerVlanValid) {
            selector.add(innerVlanCriterion);
        }
        return selector.build();
    }

    private TrafficSelector getFwdClassifierFields(TrafficSelector packet,
                                                   PiCriterion.Builder piCriterionBuilder) {
        final EthCriterion ethDst = (EthCriterion) criterion(
                packet.criteria(), Criterion.Type.ETH_DST);
        final EthCriterion ethDstMasked = (EthCriterion) criterion(
                packet.criteria(), Criterion.Type.ETH_DST_MASKED);

        // Three possible scenarios. Multicast leverages the masked criterion
        final TrafficSelector.Builder selector;
        // FIXME support Multicast
        if (ethDst == null && ethDstMasked != null) {
            log.warn("Multicast is not yet supported");
            selector = DefaultTrafficSelector.builder();
        } else if (ethDst != null) {
            // All the packets have always an ethtype criterion (at least) and additional information.
            final EthTypeCriterion ethTypeCriterion = (EthTypeCriterion) criterion(
                    packet.criteria(), Criterion.Type.ETH_TYPE);
            // Mpls case
            if (ethTypeCriterion.ethType().equals(EthType.EtherType.MPLS_UNICAST.ethType())
                    || ethTypeCriterion.ethType().equals(EthType.EtherType.MPLS_MULTICAST.ethType())) {
                // As "ip_eth_type" we use the original ethtype stored in the metadata criterion
                // and we will match on mpls as "eth_type"
                selector = DefaultTrafficSelector.builder(getMplsFwdClassFields(
                        packet, piCriterionBuilder));
            } else if (ethTypeCriterion.ethType().equals(EthType.EtherType.IPV4.ethType())
                    || ethTypeCriterion.ethType().equals(EthType.EtherType.IPV6.ethType())) {
                // Eth type is ipv4 or ipv6
                short ethType = ethTypeCriterion.ethType().toShort();
                selector = DefaultTrafficSelector.builder(getIpFwdClassSelector(
                        packet, ethType, piCriterionBuilder));
            } else {
                // In theory this is not needed - other eth types do not have an ethDst nor a ethDstMask
                if (log.isDebugEnabled()) {
                    log.debug("Packet {} skips fwd classifier step ethtype not supported", packet);
                }
                selector = DefaultTrafficSelector.builder();
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Packet {} skips fwd classifier step", packet);
            }
            selector = DefaultTrafficSelector.builder();
        }
        return selector.build();
    }


    // Returns the traffic selector generated for the mpls fwd classifier
    private TrafficSelector getMplsFwdClassFields(TrafficSelector packet,
                                                  PiCriterion.Builder piCriterionBuilder) {
        final MetadataCriterion metadataCriterion = (MetadataCriterion) criterion(
                packet.criteria(), Criterion.Type.METADATA);
        final PiCriterion piCriterion = (PiCriterion) criterion(
                packet.criteria(), Criterion.Type.PROTOCOL_INDEPENDENT);
        final PortCriterion inPortCriterion = (PortCriterion) criterion(
                packet.criteria(), Criterion.Type.IN_PORT);
        final EthCriterion ethDst = (EthCriterion) criterion(
                packet.criteria(), Criterion.Type.ETH_DST);

        // Get the pi criterion and verify if eth_type and ip_eth_type are already present
        if (piCriterion != null) {
            piCriterion.fieldMatches().forEach(piCriterionBuilder::add);
            Optional<PiFieldMatch> piFieldMatch = piCriterion.fieldMatch(P4InfoConstants.HDR_ETH_TYPE);
            if (!piFieldMatch.isPresent()) {
                piCriterionBuilder.matchTernary(P4InfoConstants.HDR_ETH_TYPE,
                        Ethernet.MPLS_UNICAST, ETH_TYPE_EXACT_MASK);
            }
            piFieldMatch = piCriterion.fieldMatch(P4InfoConstants.HDR_IP_ETH_TYPE);
            if (!piFieldMatch.isPresent()) {
                if (metadataCriterion != null) {
                    long ethType = metadataCriterion.metadata();
                    short ipEthType = EthType.EtherType.lookup((short) ethType).ethType().toShort();
                    piCriterionBuilder.matchExact(P4InfoConstants.HDR_IP_ETH_TYPE,
                            ipEthType);
                }
            }
        } else {
            piCriterionBuilder.matchTernary(P4InfoConstants.HDR_ETH_TYPE,
                    Ethernet.MPLS_UNICAST, ETH_TYPE_EXACT_MASK);
            if (metadataCriterion != null) {
                long ethType = metadataCriterion.metadata();
                short ipEthType = EthType.EtherType.lookup((short) ethType).ethType().toShort();
                piCriterionBuilder.matchExact(P4InfoConstants.HDR_IP_ETH_TYPE,
                        ipEthType);
            }
        }

        // Adds the remaining criterions: inport and eth_dst
        final TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        if (inPortCriterion != null) {
            selector.add(inPortCriterion);
        }
        if (ethDst != null) {
            selector.matchEthDstMasked(ethDst.mac(), MacAddress.EXACT_MASK);
        }
        return selector.build();

    }

    // Returns the traffic selector generated for the ip fwd classifier
    private TrafficSelector getIpFwdClassSelector(TrafficSelector packet,
                                                  short ethType,
                                                  PiCriterion.Builder piCriterionBuilder) {

        final PiCriterion piCriterion = (PiCriterion) criterion(
                packet.criteria(), Criterion.Type.PROTOCOL_INDEPENDENT);
        final PortCriterion inPortCriterion = (PortCriterion) criterion(
                packet.criteria(), Criterion.Type.IN_PORT);
        final EthCriterion ethDst = (EthCriterion) criterion(
                packet.criteria(), Criterion.Type.ETH_DST);

        // Get the pi criterion and verify if eth_type is already present
        if (piCriterion != null) {
            piCriterion.fieldMatches().forEach(piCriterionBuilder::add);
            Optional<PiFieldMatch> piFieldMatch = piCriterion.fieldMatch(P4InfoConstants.HDR_IP_ETH_TYPE);
            if (!piFieldMatch.isPresent()) {
                piCriterionBuilder.matchExact(P4InfoConstants.HDR_IP_ETH_TYPE, ethType);
            }
        } else {
            piCriterionBuilder.matchExact(P4InfoConstants.HDR_IP_ETH_TYPE, ethType);
        }

        // Adds the remaining criterions: inport and eth_dst, and eth_dst_mask
        final TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        if (inPortCriterion != null) {
            selector.add(inPortCriterion);
        }
        // FIXME support Multicast
        if (ethDst != null) {
            selector.matchEthDstMasked(ethDst.mac(), MacAddress.EXACT_MASK);
        }
        return selector.build();
    }

    // True if the are no matching flows or none of the flows belong to port vlan table
    private boolean portVlanTableMiss(List<PiTableEntry> matchedTableEntries) {
        return matchedTableEntries.stream().noneMatch(matchedTableEntry ->
                matchedTableEntry.table().equals(P4InfoConstants.FABRIC_INGRESS_FILTERING_INGRESS_PORT_VLAN));
    }

    // True if the are no matching flows or none of the flows belong to fwd classifier table
    private boolean fwdClassifierTableMiss(List<PiTableEntry> matchedTableEntries) {
        return matchedTableEntries.stream().noneMatch(matchedTableEntry ->
                matchedTableEntry.table().equals(P4InfoConstants.FABRIC_INGRESS_FILTERING_FWD_CLASSIFIER));
    }

}
