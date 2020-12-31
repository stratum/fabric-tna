// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package org.stratumproject.fabric.tna.behaviour.traceable;

import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
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
import org.onosproject.net.flow.criteria.VlanIdCriterion;
import org.onosproject.net.pi.model.PiMatchType;
import org.onosproject.net.pi.model.PiPipeconf;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiFieldMatch;
import org.onosproject.net.pi.runtime.PiTableAction;
import org.onosproject.net.pi.runtime.PiTableEntry;
import org.onosproject.net.pi.runtime.PiTernaryFieldMatch;
import org.onosproject.net.pi.service.PiTranslationException;
import org.onosproject.net.pi.service.PiTranslationService;
import org.stratumproject.fabric.tna.behaviour.FabricCapabilities;
import org.stratumproject.fabric.tna.behaviour.P4InfoConstants;

import java.util.List;
import java.util.Map;
import java.util.Objects;

import static org.stratumproject.fabric.tna.behaviour.FabricUtils.ACL_CRITERIA;
import static org.stratumproject.fabric.tna.behaviour.FabricUtils.criterion;

/**
 * Implementation of the acl control block for fabric-tna.
 */
class PipelineTraceableAcl extends AbstractPipelineTraceableCtrl {

    /**
     * Creates a new instance with the given capabilities.
     *
     * @param capabilities capabilities
     * @param pipeconf pipeconf
     * @param piTranslationService pi translation service
     */
    public PipelineTraceableAcl(FabricCapabilities capabilities, PiPipeconf pipeconf,
                                PiTranslationService piTranslationService) {
        super(capabilities, pipeconf, piTranslationService, DataPlaneEntity.Type.FLOWRULE);
        this.tableIds = Lists.newArrayList(
                P4InfoConstants.FABRIC_INGRESS_ACL_ACL
        );
    }

    @Override
    public PipelineTraceableOutput apply(PipelineTraceableInput input) {
        // Init steps.
        FabricTraceableMetadata.Builder metadataBuilder = getMetadata(input.ingressPacket());
        TrafficSelector packet = input.ingressPacket().packet();
        PipelineTraceableOutput.Builder outputBuilder = PipelineTraceableOutput.builder();
        PipelineTraceableHitChain currentHitChain = PipelineTraceableHitChain.emptyHitChain();
        PipelineTraceablePacket egressPacket = new PipelineTraceablePacket(
                input.ingressPacket().packet(), metadataBuilder.build());

        List<DataPlaneEntity> aclFlows = getDataPlaneEntity(input.deviceState());
        if (aclFlows.isEmpty()) {
            currentHitChain.setEgressPacket(egressPacket);
            currentHitChain.dropped();
            return outputBuilder.appendToLog("There are no flows for " + getClass().getSimpleName() +
                    ". Aborting")
                    .noFlows()
                    .addHitChain(currentHitChain)
                    .build();
        }

        List<PiTableEntry> matchedTableEntries = Lists.newArrayList();
        PiTableEntry bestTer = null;
        Map<PiTableEntry, DataPlaneEntity> mapping = Maps.newHashMap();
        for (DataPlaneEntity dataPlaneEntity : aclFlows) {

            if (log.isDebugEnabled()) {
                log.debug("Packet before acl augmentation {}", packet);
            }
            TrafficSelector packetForPiTranslation = augmentPacket(packet, metadataBuilder.build(),
                    dataPlaneEntity);
            if (packetForPiTranslation.equals(DefaultTrafficSelector.emptySelector())) {
                log.debug("matchAclTables failed due to augmentation error");
                continue;
            }
            if (log.isDebugEnabled()) {
                log.debug("Packet after acl augmentation {}", packetForPiTranslation);
            }

            PiTableEntry tableEntry = matchTables(packetForPiTranslation, dataPlaneEntity);
            if (tableEntry != null) {
                bestTer = TraceableUtils.selectBestTerEntry(bestTer, tableEntry);
                mapping.put(tableEntry, dataPlaneEntity);
            }
        }

        if (bestTer != null) {
            matchedTableEntries.add(bestTer);
            currentHitChain.addDataPlaneEntity(mapping.get(bestTer));
        }

        matchedTableEntries.forEach(matchedTableEntry -> applyTables(metadataBuilder, matchedTableEntry));

        egressPacket = new PipelineTraceablePacket(
                input.ingressPacket().packet(), metadataBuilder.build());
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
                    .allMatch(fieldMatch -> {
                        // We should find the relative ternary match of the packet
                        PiFieldMatch tobeMatched = packetTranslated.matchKey().fieldMatches().stream()
                                .filter(matches -> Objects.equals(matches.type(), PiMatchType.TERNARY) &&
                                        Objects.equals(fieldMatch.fieldId(), matches.fieldId()))
                                .findFirst()
                                .orElse(null);
                        return TraceableUtils.ternaryMatch((PiTernaryFieldMatch) fieldMatch,
                                (PiTernaryFieldMatch) tobeMatched);
                    }) ? matchFlowTranslated : null;
        } catch (PiTranslationException e) {
            log.debug("matchAclTables failed due to PI translation error: {}", e.getMessage());
        }
        return null;
    }

    @Override
    public TrafficSelector augmentPacket(TrafficSelector packet, FabricTraceableMetadata metadata,
                                         DataPlaneEntity dataPlaneEntity) {
        TrafficSelector.Builder packetForPiTranslation = DefaultTrafficSelector.builder();
        PiCriterion.Builder piCriterionForTranslation = PiCriterion.builder();

        if (log.isDebugEnabled()) {
            log.debug("Augments packet with acl selector");
        }
        final PiCriterion piCriterion = (PiCriterion) criterion(
                packet.criteria(), Criterion.Type.PROTOCOL_INDEPENDENT);

        // Get the pi criterion and copy in the builder
        if (piCriterion != null) {
            piCriterion.fieldMatches().forEach(piCriterionForTranslation::add);
        }

        // We filter out the ACL criteria that are not supported
        packet.criteria()
                .stream()
                .filter(criterion -> ACL_CRITERIA.contains(criterion.type()))
                .forEach(criterion -> {
                    if (!(criterion instanceof VlanIdCriterion) ||
                            !((VlanIdCriterion) criterion).vlanId().equals(VlanId.NONE)) {
                        packetForPiTranslation.add(criterion);
                    }
                });

        // Add fields coming from the metadata
        if (!metadata.getVlanId().equals(VlanId.NONE)) {
            packetForPiTranslation.matchVlanId(metadata.getVlanId());
        }

        try {
            return packetForPiTranslation.matchPi(piCriterionForTranslation.build())
                    .build();
        } catch (IllegalArgumentException e) {
            log.debug("PiCriterion is empty");
        }
        return packetForPiTranslation.build();
    }

    @Override
    public void applyTables(FabricTraceableMetadata.Builder metadataBuilder, PiTableEntry piTableEntry) {
        if (piTableEntry.action().type() == PiTableAction.Type.ACTION) {
            PiAction piAction = (PiAction) piTableEntry.action();
            if (piAction.id().equals(P4InfoConstants.FABRIC_INGRESS_ACL_COPY_TO_CPU)) {
                if (log.isDebugEnabled()) {
                    log.debug("applyAclTables action COPY_TO_CPU");
                }
                metadataBuilder.setCopyToController();
            } else if (piAction.id().equals(P4InfoConstants.FABRIC_INGRESS_ACL_PUNT_TO_CPU)) {
                if (log.isDebugEnabled()) {
                    log.debug("applyAclTables action PUNT_TO_CPU");
                }
                // We reset the next id as a way to stop the packet processing after ingress
                metadataBuilder.setPuntToController();
                metadataBuilder.setSkipNext();
                metadataBuilder.setNextId(-1);
            } else {
                // FIXME do we use other actions ?
                log.warn("applyAclTables does not support action: {}", piAction);
            }
        } else {
            log.warn("applyAclTables does not support actions different from : {}",
                    PiAction.Type.ACTION);
        }
    }

}
