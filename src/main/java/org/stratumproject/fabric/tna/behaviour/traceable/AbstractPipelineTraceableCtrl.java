// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package org.stratumproject.fabric.tna.behaviour.traceable;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import org.onlab.util.ImmutableByteSequence;
import org.onosproject.net.DataPlaneEntity;
import org.onosproject.net.PipelineTraceablePacket;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.FlowEntry;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.pi.model.PiPipeconf;
import org.onosproject.net.pi.model.PiPipelineInterpreter;
import org.onosproject.net.pi.model.PiTableId;
import org.onosproject.net.pi.runtime.PiActionParam;
import org.onosproject.net.pi.service.PiTranslationService;
import org.slf4j.Logger;
import org.stratumproject.fabric.tna.behaviour.FabricCapabilities;
import org.stratumproject.fabric.tna.behaviour.P4InfoConstants;

import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import static org.slf4j.LoggerFactory.getLogger;

/**
 * Abstract implementation of a control block for fabric-tna.
 */
abstract class AbstractPipelineTraceableCtrl implements PipelineTraceableCtrl {

    protected final Logger log = getLogger(getClass());
    // Reference to the fabric capabilities and pipeconf instance
    protected FabricCapabilities capabilities;
    protected PiPipeconf pipeconf;
    // Tables belonging to this control block
    protected List<PiTableId> tableIds;
    // PiTranslationService reference for the translation step
    protected PiTranslationService piTranslationService;
    private DataPlaneEntity.Type entityType;

    /**
     * Creates a new instance of a control block with the given capabilities
     * and pipeconf.
     *
     * @param capabilities capabilities
     * @param pipeconf pipeconf
     * @param piTranslationService pi translation service
     * @param entitytype supported dataplane entity
     */
    public AbstractPipelineTraceableCtrl(FabricCapabilities capabilities, PiPipeconf pipeconf,
                                         PiTranslationService piTranslationService,
                                         DataPlaneEntity.Type entitytype) {
        this.capabilities = capabilities;
        this.pipeconf = pipeconf;
        this.piTranslationService = piTranslationService;
        this.tableIds = Lists.newArrayList();
        this.entityType = entitytype;
    }

    /**
     * Gets the dataplane entities related to this ctrl block.
     *
     * @param dataPlaneEntities the data plane entities to analyze
     * @return the data plane entities belonging to the defined table ids
     */
    protected List<DataPlaneEntity> getDataPlaneEntity(List<DataPlaneEntity> dataPlaneEntities) {
        // No table ids defined - there is something wrong here.
        if (tableIds.isEmpty()) {
            log.warn("There are no tables defined. Aborting");
            return ImmutableList.of();
        }
        // Filter by table ids
        return dataPlaneEntities.stream()
                .filter(entity -> Objects.equals(entityType, entity.getType()) &&
                        tableIds.contains(entity.getFlowEntry().table()))
                .collect(Collectors.toList());
    }

    /**
     * Creates interpreter behavior using the pipeconf.
     *
     * @return the interpreter implementation
     */
    protected PiPipelineInterpreter getInterpreter() {
        if (!this.pipeconf.hasBehaviour(PiPipelineInterpreter.class)) {
            log.warn("PiPipelineInterpreter behaviour not supported for the pipeconf {}",
                    pipeconf.id());
            return null;
        } else {
            try {
                return (PiPipelineInterpreter) pipeconf.implementation(PiPipelineInterpreter.class)
                        .orElse(null)
                        .newInstance();
            } catch (InstantiationException | IllegalAccessException e) {
                return null;
            }
        }
    }

    /**
     * Gets the packet metadata builder or instantiate a new if null.
     *
     * @param packet the input packet
     * @return the packet metadata builder instance
     */
    protected FabricTraceableMetadata.Builder getMetadata(PipelineTraceablePacket packet) {
        return packet.metadata() == null ? FabricTraceableMetadata.builder() :
                FabricTraceableMetadata.builder((FabricTraceableMetadata) packet.metadata());
    }

    /**
     * Creates a flow rule from the packet representation (traffic selector)
     * that is processed later by the PI translation service.
     *
     * @param matchFlow the matching flow
     * @param packetForPiTranslation the packet representation
     * @return the flowrule representing the packet
     */
    protected FlowRule.Builder createFlowForPiTranslation(FlowEntry matchFlow,
                                                          TrafficSelector packetForPiTranslation) {
        return DefaultFlowRule.builder()
                .withCookie(0)
                .makeTemporary(0)
                .forDevice(matchFlow.deviceId())
                .withPriority(FlowRule.MIN_PRIORITY)
                .forTable(matchFlow.table())
                .withSelector(packetForPiTranslation)
                // We dont'care of the treatment, we represent the packet using only the criteria
                // and because it does not affect the matching result, but we need to set it before
                // comparing flow entry to avoid internal errors in PI translation service
                .withTreatment(matchFlow.treatment());
    }

    /**
     * Retrieves the next id from a collection of pi action param.
     *
     * @param params collection of pi action param
     * @return the next id
     */
    protected int getNextIdFromParams(Collection<PiActionParam> params) {
        // Restore the original size - if the table model uses a smaller bitwidth
        int nextId;
        try {
            nextId = params.stream()
                    .findFirst()
                    .orElse(new PiActionParam(P4InfoConstants.NEXT_ID, -1))
                    .value()
                    .fit(Integer.SIZE)
                    .asReadOnlyBuffer()
                    .getInt();
        } catch (ImmutableByteSequence.ByteSequenceTrimException e) {
            log.debug("getNextIdFromParams failed due to trim error: {}", e.getMessage());
            nextId = -1;
        }
        return nextId;
    }

    /**
     * Retrieves the group id from a collection of pi action param.
     *
     * @param params collection of pi action param
     * @return the next id
     */
    protected int getGroupIdFromParams(Collection<PiActionParam> params) {
        // Restore the original size - if the table model uses a smaller bitwidth
        int groupId;
        try {
            groupId = params.stream()
                    .findFirst()
                    .orElse(new PiActionParam(P4InfoConstants.GROUP_ID,
                            -1))
                    .value()
                    .fit(Integer.SIZE)
                    .asReadOnlyBuffer()
                    .getInt();
        } catch (ImmutableByteSequence.ByteSequenceTrimException e) {
            log.debug("getGroupIdFromParams failed due to trim error: {}", e.getMessage());
            groupId = -1;
        }
        return groupId;
    }

}
