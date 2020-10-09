// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package org.stratumproject.fabric.tna.behaviour.traceable;

import com.google.common.collect.Lists;
import org.onosproject.net.DeviceId;
import org.onosproject.net.PipelineTraceablePacket;
import org.onosproject.net.behaviour.PipelineTraceable;
import org.onosproject.net.driver.Behaviour;
import org.onosproject.net.pi.service.PiTranslationService;
import org.slf4j.Logger;
import org.stratumproject.fabric.tna.behaviour.AbstractFabricHandlerBehavior;
import org.stratumproject.fabric.tna.behaviour.FabricCapabilities;

import java.util.List;

import static org.slf4j.LoggerFactory.getLogger;

/**
 * Abstract implementation of PipelineTraceable for the fabric-tna pipeconf
 * behaviors.
 * <p>
 * All sub-classes must implement a default constructor, used by the abstract
 * projectable model (i.e., {@link org.onosproject.net.Device#as(Class)}.
 */
abstract class AbstractFabricPipelineTraceable extends AbstractFabricHandlerBehavior
        implements PipelineTraceable {

    protected final Logger log = getLogger(getClass());
    protected DeviceId deviceId;
    protected String driverName;
    protected List<PipelineTraceableCtrl> ingressPipeline = Lists.newArrayList();
    protected List<PipelineTraceableCtrl> egressPipeline = Lists.newArrayList();

    protected AbstractFabricPipelineTraceable(FabricCapabilities capabilities) {
        super(capabilities);
    }

    public AbstractFabricPipelineTraceable() {
        // Do nothing
    }

    @Override
    public void init() {
        this.deviceId = this.data().deviceId();
        this.driverName = this.data().driver().name();
        PiTranslationService piTranslationService = this.handler().get(PiTranslationService.class);
        // Here we compose the ingress pipeline. Let's add the SPGW only if supported
        if (capabilities.supportSpgw()) {
            ingressPipeline.add(new PipelineTraceableSpgw(capabilities, pipeconf, piTranslationService));
        }
        // Here we add the core ingress pipeline
        List<PipelineTraceableCtrl> coreIngressPipeline = Lists.newArrayList(
                new PipelineTraceableFiltering(capabilities, pipeconf, piTranslationService),
                new PipelineTraceableForwarding(capabilities, pipeconf, piTranslationService),
                new PipelineTraceableAcl(capabilities, pipeconf, piTranslationService),
                new PipelineTraceableNext(capabilities, pipeconf, piTranslationService));
        ingressPipeline.addAll(coreIngressPipeline);
        // Here we add the core egress pipeline
        List<PipelineTraceableCtrl> coreEressPipeline = Lists.newArrayList(
            new PipelineTraceableEgress(capabilities, pipeconf, piTranslationService));
        egressPipeline.addAll(coreEressPipeline);
    }

    // Returns the related implementation of the behavior class
    protected <B extends Behaviour> B getBehavior(Class<B> behavior) {
        if (!this.handler().hasBehaviour(behavior)) {
            log.warn("{} behaviour not supported for device {}", behavior, deviceId);
            return null;
        }
        return this.handler().behaviour(behavior);
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

}
