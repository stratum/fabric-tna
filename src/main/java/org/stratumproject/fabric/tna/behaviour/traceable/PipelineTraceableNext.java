// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0

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
import org.onosproject.net.flow.criteria.PiCriterion;
import org.onosproject.net.pi.model.PiPipeconf;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiActionParam;
import org.onosproject.net.pi.runtime.PiActionProfileGroupId;
import org.onosproject.net.pi.runtime.PiFieldMatch;
import org.onosproject.net.pi.runtime.PiTableAction;
import org.onosproject.net.pi.runtime.PiTableEntry;
import org.onosproject.net.pi.service.PiTranslationException;
import org.onosproject.net.pi.service.PiTranslationService;
import org.stratumproject.fabric.tna.behaviour.FabricCapabilities;
import org.stratumproject.fabric.tna.behaviour.P4InfoConstants;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import static org.stratumproject.fabric.tna.behaviour.FabricUtils.criterion;

/**
 * Implementation of the next control block for fabric-tna.
 */
class PipelineTraceableNext extends AbstractPipelineTraceableCtrl {

    /**
     * Creates a new instance with the given capabilities.
     *
     * @param capabilities capabilities
     * @param pipeconf pipeconf
     * @param piTranslationService pi translation service
     */
    public PipelineTraceableNext(FabricCapabilities capabilities, PiPipeconf pipeconf,
                                 PiTranslationService piTranslationService) {
        super(capabilities, pipeconf, piTranslationService);
        // FIXME support XConnect
        this.tableIds = Lists.newArrayList(
                P4InfoConstants.FABRIC_INGRESS_NEXT_HASHED,
                P4InfoConstants.FABRIC_INGRESS_NEXT_MULTICAST,
                P4InfoConstants.FABRIC_INGRESS_NEXT_NEXT_VLAN
        );
    }

    @Override
    public PipelineTraceableOutput apply(PipelineTraceableInput input) {
        FabricTraceableMetadata.Builder metadataBuilder = getMetadata(input.ingressPacket());
        TrafficSelector packet = input.ingressPacket().getPacket();
        PipelineTraceableOutput.Builder outputBuilder = PipelineTraceableOutput.builder();
        PipelineTraceableHitChain currentHitChain = PipelineTraceableHitChain.emptyHitChain();
        PipelineTraceablePacket egressPacket = new PipelineTraceablePacket(
                input.ingressPacket().getPacket(), metadataBuilder.build());

        // Skips next if the relative metadata is set.
        // Note that this might not be a failure.
        if (metadataBuilder.build().isSkipNext()) {
            currentHitChain.setEgressPacket(egressPacket);
            currentHitChain.pass();
            return outputBuilder.appendToLog("Skip " + getClass().getSimpleName())
                    .addHitChain(currentHitChain)
                    .build();
        }

        List<DataPlaneEntity> nextFlows = getDataPlaneEntity(input.deviceState());
        if (nextFlows.isEmpty()) {
            currentHitChain.setEgressPacket(egressPacket);
            currentHitChain.dropped();
            return outputBuilder.appendToLog("There are no flows for " + getClass().getSimpleName() +
                    ". Aborting")
                    .noFlows()
                    .addHitChain(currentHitChain)
                    .build();
        }

        List<PiTableEntry> matchedTableEntries = Lists.newArrayList();
        for (DataPlaneEntity dataPlaneEntity : nextFlows) {

            TrafficSelector packetForPiTranslation = augmentPacket(packet, metadataBuilder.build(),
                    dataPlaneEntity);
            if (packetForPiTranslation.equals(DefaultTrafficSelector.emptySelector())) {
                log.debug("matchForwardingTables failed due to augmentation error");
                continue;
            }

            PiTableEntry tableEntry = matchTables(packetForPiTranslation, dataPlaneEntity);
            if (tableEntry != null) {
                matchedTableEntries.add(tableEntry);
                currentHitChain.addDataPlaneEntity(dataPlaneEntity);
            }
        }
        // Apply the matched flow rule
        matchedTableEntries.forEach(matchedTableEntry -> applyTables(metadataBuilder, matchedTableEntry));

        // Finally build the output that will be used as input for the next block
        egressPacket = new PipelineTraceablePacket(
                input.ingressPacket().getPacket(), metadataBuilder.build());
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
            log.debug("matchFilteringTables failed due to PI translation error: {}", e.getMessage());
        }
        return null;
    }

    @Override
    public TrafficSelector augmentPacket(TrafficSelector packet, FabricTraceableMetadata metadata,
                                         DataPlaneEntity dataPlaneEntity) {
        TrafficSelector.Builder packetForPiTranslation = DefaultTrafficSelector.builder();
        PiCriterion.Builder piCriterionForTranslation = PiCriterion.builder();

        // FIXME support for XConnect
        final PiCriterion piCriterion = (PiCriterion) criterion(
                packet.criteria(), Criterion.Type.PROTOCOL_INDEPENDENT);

        // Copy all the pi criterion and add if necessary the next id criterion
        if (piCriterion != null) {
            piCriterion.fieldMatches().forEach(piFieldMatch ->
                    piCriterionForTranslation.addMatchField(piFieldMatch.fieldId(), piFieldMatch));
            Optional<PiFieldMatch> piFieldMatch = piCriterion.fieldMatch(P4InfoConstants.HDR_NEXT_ID);
            if (!piFieldMatch.isPresent()) {
                piCriterionForTranslation.matchExact(P4InfoConstants.HDR_NEXT_ID, metadata.getNextId())
                        .build();
            }
        } else {
            // There is no pi criterion in the packet - build from scratch
            piCriterionForTranslation.matchExact(P4InfoConstants.HDR_NEXT_ID, metadata.getNextId())
                    .build();
        }

        // Finally builds up the pi criterion and add to the selector before terminating
        // In this case there is no need for exceptions handling
        return packetForPiTranslation.matchPi(piCriterionForTranslation.build())
                .build();
    }

    @Override
    public void applyTables(FabricTraceableMetadata.Builder metadataBuilder, PiTableEntry piTableEntry) {
        // FIXME support for XConnect
        if (piTableEntry.action().type() == PiTableAction.Type.ACTION) {
            PiAction piAction = (PiAction) piTableEntry.action();
            if (piAction.id().equals(P4InfoConstants.FABRIC_INGRESS_NEXT_SET_VLAN)) {
                if (log.isDebugEnabled()) {
                    log.debug("applyNextTables action SET_VLAN {}", piAction.parameters());
                }
                // Rewrite vlan before egressing
                short vlanId = piAction.parameters()
                        .stream()
                        .findFirst()
                        .orElse(new PiActionParam(P4InfoConstants.VLAN_ID,
                                VlanId.NONE.toShort()))
                        .value()
                        .asReadOnlyBuffer()
                        .getShort();
                metadataBuilder.setVlanId(vlanId);
            } else if (piAction.id().equals(P4InfoConstants.FABRIC_INGRESS_NEXT_SET_MCAST_GROUP_ID)) {
                if (log.isDebugEnabled()) {
                    log.debug("applyNextTables action SET_MCAST_GROUP_ID {}", piAction.parameters());
                }
                // Retrieve the group id
                metadataBuilder.setGroupId(getGroupIdFromParams(piAction.parameters()));
            } else {
                log.warn("applyNextTables does not support action: {}", piAction);
            }
        } else if (piTableEntry.action().type() == PiTableAction.Type.ACTION_PROFILE_GROUP_ID) {
            PiActionProfileGroupId piActionProfileGroupId = (PiActionProfileGroupId) piTableEntry.action();
            if (log.isDebugEnabled()) {
                log.debug("applyNextTables action SET_ACTION_PROFILE_GROUP_ID {}", piActionProfileGroupId.id());
            }
            metadataBuilder.setGroupId(piActionProfileGroupId.id());
        } else {
            log.warn("applyNextTables does not support actions different from : {} and {}",
                    PiAction.Type.ACTION, PiAction.Type.ACTION_PROFILE_GROUP_ID);
        }
    }

    @Override
    protected List<DataPlaneEntity> getDataPlaneEntity(List<DataPlaneEntity> dataPlaneEntities) {
        List<DataPlaneEntity> filteredEntities = super.getDataPlaneEntity(dataPlaneEntities);
        // Filter by type
        return filteredEntities.stream()
                .filter(entity -> entity.getType() == DataPlaneEntity.Type.FLOWRULE)
                .collect(Collectors.toList());
    }

}
