// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0

package org.stratumproject.fabric.tna.behaviour.traceable;

import com.google.common.collect.ImmutableList;
import org.onosproject.net.DataPlaneEntity;
import org.onosproject.net.PipelineTraceableHitChain;
import org.onosproject.net.PipelineTraceableInput;
import org.onosproject.net.PipelineTraceableOutput;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.pi.model.PiPipeconf;
import org.onosproject.net.pi.runtime.PiTableEntry;
import org.onosproject.net.pi.service.PiTranslationService;
import org.stratumproject.fabric.tna.behaviour.FabricCapabilities;

/**
 * Implementation of the spgw control block for fabric-tna.
 */
class PipelineTraceableSpgw extends AbstractPipelineTraceableCtrl {

    /**
     * Creates a new instance with the given capabilities.
     *
     * @param capabilities capabilities
     * @param pipeconf pipeconf
     * @param piTranslationService pi translation service
     */
    public PipelineTraceableSpgw(FabricCapabilities capabilities, PiPipeconf pipeconf,
                                 PiTranslationService piTranslationService) {
        super(capabilities, pipeconf, piTranslationService);
    }

    @Override
    public PipelineTraceableOutput apply(PipelineTraceableInput input) {
        // FIXME temporary fake implementation
        return PipelineTraceableOutput.builder()
                .addHitChain(new PipelineTraceableHitChain(null, ImmutableList.of(),
                        input.ingressPacket()))
                .build();
    }

    @Override
    public PiTableEntry matchTables(TrafficSelector packet, DataPlaneEntity dataPlaneEntity) {
        return null;
    }

    @Override
    public TrafficSelector augmentPacket(TrafficSelector packet, FabricTraceableMetadata metadata,
                                         DataPlaneEntity dataPlaneEntity) {
        return null;
    }

    @Override
    public void applyTables(FabricTraceableMetadata.Builder metadataBuilder, PiTableEntry piTableEntry) {

    }

}
