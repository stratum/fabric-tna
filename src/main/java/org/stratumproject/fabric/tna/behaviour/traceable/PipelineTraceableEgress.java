// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package org.stratumproject.fabric.tna.behaviour.traceable;

import com.google.common.collect.Lists;
import org.onlab.packet.VlanId;
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
import org.onosproject.net.flow.criteria.EthTypeCriterion;
import org.onosproject.net.flow.criteria.MetadataCriterion;
import org.onosproject.net.flow.criteria.PiCriterion;
import org.onosproject.net.pi.model.PiPipeconf;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiFieldMatch;
import org.onosproject.net.pi.runtime.PiTableAction;
import org.onosproject.net.pi.runtime.PiTableEntry;
import org.onosproject.net.pi.service.PiTranslationException;
import org.onosproject.net.pi.service.PiTranslationService;
import org.stratumproject.fabric.tna.behaviour.FabricCapabilities;
import org.stratumproject.fabric.tna.behaviour.P4InfoConstants;

import java.util.List;
import java.util.Optional;

import static org.onlab.packet.EthType.EtherType.MPLS_UNICAST;
import static org.stratumproject.fabric.tna.behaviour.FabricUtils.criterion;

/**
 * Implementation of the egress control block for fabric-tna.
 */
class PipelineTraceableEgress extends AbstractPipelineTraceableCtrl {

    /**
     * Creates a new instance with the given capabilities.
     *
     * @param capabilities capabilities
     * @param pipeconf pipeconf
     * @param piTranslationService pi translation service
     */
    public PipelineTraceableEgress(FabricCapabilities capabilities, PiPipeconf pipeconf,
                                   PiTranslationService piTranslationService) {
        super(capabilities, pipeconf, piTranslationService, DataPlaneEntity.Type.FLOWRULE);
        this.tableIds = Lists.newArrayList(P4InfoConstants.FABRIC_EGRESS_EGRESS_NEXT_EGRESS_VLAN);
    }

    @Override
    public PipelineTraceableOutput apply(PipelineTraceableInput input) {
        FabricTraceableMetadata.Builder metadataBuilder = getMetadata(input.ingressPacket());
        TrafficSelector packet = input.ingressPacket().packet();
        PipelineTraceableOutput.Builder outputBuilder = PipelineTraceableOutput.builder();
        PipelineTraceableHitChain currentHitChain = PipelineTraceableHitChain.emptyHitChain();
        PipelineTraceablePacket egressPacket = new PipelineTraceablePacket(
            input.ingressPacket().packet(), metadataBuilder.build());

        List<DataPlaneEntity> egressFlows = getDataPlaneEntity(input.deviceState());
        if (egressFlows.isEmpty()) {
            currentHitChain.setEgressPacket(egressPacket);
            currentHitChain.dropped();
            return outputBuilder.appendToLog("There are no flows for " + getClass().getSimpleName() +
                ". Aborting")
                .noFlows()
                .addHitChain(currentHitChain)
                .build();
        }

        List<PiTableEntry> matchedTableEntries = Lists.newArrayList();
        for (DataPlaneEntity dataPlaneEntity : egressFlows) {

            if (log.isDebugEnabled()) {
                log.debug("Packet before egress augmentation {}", packet);
            }
            TrafficSelector packetForPiTranslation = augmentPacket(packet, metadataBuilder.build(),
                dataPlaneEntity);
            if (packetForPiTranslation.equals(DefaultTrafficSelector.emptySelector())) {
                log.debug("matchEgressTables failed due to augmentation error");
                continue;
            }
            if (log.isDebugEnabled()) {
                log.debug("Packet after egress augmentation {}", packetForPiTranslation);
            }

            PiTableEntry tableEntry = matchTables(packetForPiTranslation, dataPlaneEntity);
            if (tableEntry != null) {
                matchedTableEntries.add(tableEntry);
                currentHitChain.addDataPlaneEntity(dataPlaneEntity);
            }
        }

        // Egress table drops packets on table miss
        if (matchedTableEntries.isEmpty()) {
            currentHitChain.setEgressPacket(egressPacket);
            currentHitChain.dropped();
            return outputBuilder.appendToLog("There are no matches for " + getClass().getSimpleName() +
                ". Aborting")
                .noFlows()
                .addHitChain(currentHitChain)
                .build();
        }

        // Apply the matched flow rule
        matchedTableEntries.forEach(matchedTableEntry -> applyTables(metadataBuilder, matchedTableEntry));

        // Updates the packet and exits
        if (isPiPacket(input.ingressPacket().packet())) {
            egressPacket = updatePiPacket(new PipelineTraceablePacket(input.ingressPacket().packet(),
                metadataBuilder.build()));
        } else {
            egressPacket = updatePacket(new PipelineTraceablePacket(input.ingressPacket().packet(),
                metadataBuilder.build()));
        }

        currentHitChain.setEgressPacket(egressPacket);
        currentHitChain.pass();
        return outputBuilder.addHitChain(currentHitChain)
            .build();
    }

    @Override
    public PiTableEntry matchTables(TrafficSelector packetForPiTranslation, DataPlaneEntity dataPlaneEntity) {
        FlowEntry flowEntry = dataPlaneEntity.getFlowEntry();
        FlowRule packetFlow = createFlowForPiTranslation(flowEntry, packetForPiTranslation)
            .build();

        try {
            PiTableEntry packetTranslated =
                piTranslationService.flowRuleTranslator().translate(packetFlow, pipeconf);
            PiTableEntry matchFlowTranslated =
                piTranslationService.flowRuleTranslator().translate(flowEntry, pipeconf);
            return matchFlowTranslated.matchKey().fieldMatches().stream()
                .allMatch(fieldMatch -> packetTranslated.matchKey().fieldMatches().contains(fieldMatch)) ?
                matchFlowTranslated : null;
        } catch (PiTranslationException e) {
            log.debug("matchNextTables failed due to PI translation error: {}", e.getMessage());
        }
        return null;
    }

    @Override
    public TrafficSelector augmentPacket(TrafficSelector packet, FabricTraceableMetadata metadata,
                                         DataPlaneEntity dataPlaneEntity) {
        TrafficSelector.Builder packetForPiTranslation = DefaultTrafficSelector.builder();
        PiCriterion.Builder piCriterionForTranslation = PiCriterion.builder();

        if (log.isDebugEnabled()) {
            log.debug("Augments packet with egress selector");
        }
        final PiCriterion piCriterion = (PiCriterion) criterion(
            packet.criteria(), Criterion.Type.PROTOCOL_INDEPENDENT);
        // Copy all the pi criterion and add if necessary the eg_port criterion
        if (piCriterion != null) {
            piCriterion.fieldMatches().forEach(piCriterionForTranslation::add);
            Optional<PiFieldMatch> piFieldMatch = piCriterion.fieldMatch(P4InfoConstants.HDR_EG_PORT);
            if (!piFieldMatch.isPresent()) {
                piCriterionForTranslation.matchExact(P4InfoConstants.HDR_EG_PORT,
                    metadata.getOutPort().toLong())
                    .build();
            }
        } else {
            // There is no pi criterion in the packet - build from scratch
            piCriterionForTranslation.matchExact(P4InfoConstants.HDR_EG_PORT,
                metadata.getOutPort().toLong())
                .build();
        }

        // Vlan cannot be NONE at this point
        if (metadata.getVlanId().equals(VlanId.NONE)) {
            return packetForPiTranslation.build();
        }

        return packetForPiTranslation.matchVlanId(metadata.getVlanId())
            .matchPi(piCriterionForTranslation.build())
            .build();
    }

    @Override
    public void applyTables(FabricTraceableMetadata.Builder metadataBuilder, PiTableEntry piTableEntry) {
        // FIXME support for Double VLAN termination
        if (piTableEntry.action().type() == PiTableAction.Type.ACTION) {
            PiAction piAction = (PiAction) piTableEntry.action();
            if (piAction.id().equals(P4InfoConstants.FABRIC_EGRESS_EGRESS_NEXT_PUSH_VLAN)) {
                if (log.isDebugEnabled()) {
                    log.debug("applyEgressTables action PUSH_VLAN");
                }
                // We are fine - no need to do anything
            } else if (piAction.id().equals(P4InfoConstants.FABRIC_EGRESS_EGRESS_NEXT_POP_VLAN)) {
                if (log.isDebugEnabled()) {
                    log.debug("applyEgressTables action POP_VLAN");
                }
                // Update the metadata information for the last time
                metadataBuilder.setVlanId(VlanId.NONE.toShort());
            } else {
                log.warn("applyEgressTables does not support action: {}", piAction);
            }
        } else {
            log.warn("applyEgressTables does not support actions different from : {}", PiAction.Type.ACTION);
        }
    }

    private boolean isPiPacket(TrafficSelector currentPacket) {
        // FIXME PI packets handling
        return false;
    }

    private PipelineTraceablePacket updatePiPacket(PipelineTraceablePacket currentPacket) {
        // FIXME PI packets handling
        return currentPacket;
    }

    private PipelineTraceablePacket updatePacket(PipelineTraceablePacket currentPacket) {
        TrafficSelector.Builder newSelector = DefaultTrafficSelector.builder(currentPacket.packet());
        FabricTraceableMetadata currentMetadata = getMetadata(currentPacket).build();
        EthTypeCriterion mplsCriterion = (EthTypeCriterion) criterion(
                currentPacket.packet().criteria(), Criterion.Type.ETH_TYPE);
        // If mpls label is valid we push the new header and store the original ethertype
        // in the metadata criterion. Otherwise we pop the mpls header and restore the ethertype
        if (currentMetadata.getMplsLabel().toInt() > 0) {
            if (log.isDebugEnabled()) {
                log.debug("updatePacketEgress PUSH_MPLS {}", currentMetadata.getMplsLabel());
            }
            Criterion ethCriterion = currentPacket.packet().getCriterion(Criterion.Type.ETH_TYPE);
            // Store the old ethertype before pushing the mpls label
            if (ethCriterion != null) {
                newSelector.matchMetadata(((EthTypeCriterion) ethCriterion).ethType().toShort());
            } else {
                log.warn("updatePacketEgress cannot derive the ethertype of the packet");
            }
            newSelector.matchEthType(MPLS_UNICAST.ethType().toShort());
            newSelector.matchMplsLabel(currentMetadata.getMplsLabel());
            newSelector.matchMplsBos(true);
        } else if (mplsCriterion != null && mplsCriterion.ethType().equals(MPLS_UNICAST.ethType())) {
            if (log.isDebugEnabled()) {
                log.debug("updatePacketEgress POP_MPLS");
            }
            // When popping MPLS we remove label and BOS
            TrafficSelector temporaryPacket = newSelector.build();
            if (temporaryPacket.getCriterion(Criterion.Type.MPLS_LABEL) != null) {
                TrafficSelector.Builder noMplsSelector = DefaultTrafficSelector.builder();
                temporaryPacket.criteria().stream().filter(c -> !c.type().equals(Criterion.Type.MPLS_LABEL) &&
                    !c.type().equals(Criterion.Type.MPLS_BOS)).forEach(noMplsSelector::add);
                newSelector = noMplsSelector;
            }
            // Restore the original ethertype
            Criterion metadataCriterion = currentPacket.packet().getCriterion(Criterion.Type.METADATA);
            // If the packet comes in with the expected elements we update it
            if (metadataCriterion != null) {
                // Get the metadata to restore the original ethertype
                long ethType = ((MetadataCriterion) metadataCriterion).metadata();
                TrafficSelector.Builder noMetadataSelector = DefaultTrafficSelector.builder();
                temporaryPacket = newSelector.build();
                temporaryPacket.criteria()
                    .stream()
                    .filter(c -> !c.type().equals(Criterion.Type.METADATA))
                    .forEach(noMetadataSelector::add);
                newSelector = noMetadataSelector;
                newSelector.matchEthType((short) ethType);
            } else {
                log.warn("updatePacketEgress cannot restore the ethertype of the packet");
            }
        }
        // Updates the VLAN id criterion and exits
        newSelector.matchVlanId(currentMetadata.getVlanId());
        return new PipelineTraceablePacket(newSelector.build(), currentMetadata);
    }

}
