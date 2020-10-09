// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0

package org.stratumproject.fabric.tna.behaviour.traceable;

import org.onosproject.net.PipelineTraceableHitChain;
import org.onosproject.net.PipelineTraceableInput;
import org.onosproject.net.PipelineTraceableOutput;
import org.onosproject.net.PipelineTraceableOutput.PipelineTraceableResult;
import org.onosproject.net.PipelineTraceablePacket;
import org.stratumproject.fabric.tna.behaviour.FabricCapabilities;

/**
 * Fabric tna implementation of the pipeline traceable behavior.
 */
public class FabricTnaPipelineTraceable extends AbstractFabricPipelineTraceable {



    /**
     * Creates a new instance of this behavior with the given capabilities.
     *
     * @param capabilities capabilities
     */
    public FabricTnaPipelineTraceable(FabricCapabilities capabilities) {
        super(capabilities);
    }

    /**
     * Create a new instance of this behaviour. Used by the abstract projectable
     * model (i.e., {@link org.onosproject.net.Device#as(Class)}.
     */
    public FabricTnaPipelineTraceable() {
        super();
    }

    @Override
    public PipelineTraceableOutput apply(PipelineTraceableInput input) {
        // Init steps
        FabricTraceableMetadata.Builder metadataBuilder = getMetadata(input.ingressPacket());
        PipelineTraceableOutput.Builder outputBuilder = PipelineTraceableOutput.builder();
        PipelineTraceableHitChain currentHitChain = PipelineTraceableHitChain.emptyHitChain();
        PipelineTraceablePacket egressPacket = new PipelineTraceablePacket(
                input.ingressPacket().getPacket(), metadataBuilder.build());

        PipelineTraceableInput ctrlInput = new PipelineTraceableInput(egressPacket, input.ingressPort(),
                input.deviceState());
        PipelineTraceableOutput ctrlOutput;
        // This object acts as an orchestrator for the traceable control blocks
        // which basically implement the ingress pipeline. This first part of the code
        // will call one by one the ctrl blocks instantiated for this traceable.
        for (PipelineTraceableCtrl traceableCtrl : this.ingressPipeline) {
            if (log.isDebugEnabled()) {
                log.debug("Packet enters {}", traceableCtrl.getClass().getSimpleName());
            }
            ctrlOutput = traceableCtrl.apply(ctrlInput);
            // Cannot be null
            if (ctrlOutput == null) {
                return outputBuilder.appendToLog("No traceable output. Aborting")
                        .dropped()
                        .addHitChain(currentHitChain)
                        .build();
            }
            // Stores log and update current hit chain
            outputBuilder.appendToLog(ctrlOutput.getLog());
            // Error - exit immediately without updating the hit chain
            if (ctrlOutput.getHitChains().size() != 1) {
                return outputBuilder.appendToLog("Too many hit chains. Aborting")
                        .dropped()
                        .addHitChain(currentHitChain)
                        .build();
            }
            ctrlOutput.getHitChains().get(0).getHitChain().forEach(currentHitChain::addDataPlaneEntity);
            currentHitChain.setEgressPacket(ctrlOutput.getHitChains().get(0).getEgressPacket());
            // Did not end well - exit
            if (ctrlOutput.getResult() != PipelineTraceableResult.SUCCESS) {
                return outputBuilder.setResult(ctrlOutput.getResult())
                        .addHitChain(currentHitChain)
                        .build();
            }
            // Finally refresh the ctrl input before jumping to the next ctrl block
            ctrlInput = new PipelineTraceableInput(currentHitChain.getEgressPacket(), input.ingressPort(),
                    input.deviceState());
        }
        // TODO Here there is the group handling of the pipeline

        // TODO Finally, here happens the egress handling where we have to emulate one table
        //  and basically modify the packet according the content of the traceable metadata

        // FIXME to be removed
        currentHitChain.pass();
        return outputBuilder.addHitChain(currentHitChain)
                .build();
    }






}
