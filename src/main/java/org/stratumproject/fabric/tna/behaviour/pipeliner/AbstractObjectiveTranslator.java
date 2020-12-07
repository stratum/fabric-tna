// Copyright 2018-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-1.0

package org.stratumproject.fabric.tna.behaviour.pipeliner;

import org.onosproject.net.DeviceId;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.instructions.Instruction;
import org.onosproject.net.flowobjective.Objective;
import org.onosproject.net.flowobjective.ObjectiveError;
import org.onosproject.net.pi.model.PiPipelineInterpreter;
import org.onosproject.net.pi.model.PiTableId;
import org.onosproject.net.pi.runtime.PiAction;
import org.slf4j.Logger;
import org.stratumproject.fabric.tna.behaviour.FabricCapabilities;
import org.stratumproject.fabric.tna.behaviour.FabricInterpreter;

import static com.google.common.base.Preconditions.checkNotNull;
import static java.lang.String.format;
import static org.slf4j.LoggerFactory.getLogger;

/**
 * Abstract implementation of a pipeliner logic for the fabric-tna pipeconf.
 */
abstract class AbstractObjectiveTranslator<T extends Objective> {

    protected final Logger log = getLogger(this.getClass());

    protected final FabricCapabilities capabilities;
    protected final DeviceId deviceId;

    private final PiPipelineInterpreter interpreter;

    AbstractObjectiveTranslator(DeviceId deviceId, FabricCapabilities capabilities) {
        this.deviceId = checkNotNull(deviceId);
        this.capabilities = checkNotNull(capabilities);
        this.interpreter = new FabricInterpreter(capabilities);
    }

    public ObjectiveTranslation translate(T obj) {
        try {
            return doTranslate(obj);
        } catch (FabricPipelinerException e) {
            log.warn("Cannot translate {}: {} [{}]",
                     obj.getClass().getSimpleName(), e.getMessage(), obj);
            return ObjectiveTranslation.ofError(e.objectiveError());
        }
    }

    public abstract ObjectiveTranslation doTranslate(T obj)
            throws FabricPipelinerException;

    public FlowRule flowRule(T obj, PiTableId tableId, TrafficSelector selector,
                             TrafficTreatment treatment)
            throws FabricPipelinerException {
        return flowRule(obj, tableId, selector, treatment, obj.priority());
    }

    public FlowRule flowRule(T obj, PiTableId tableId, TrafficSelector selector,
                             TrafficTreatment treatment, Integer priority)
            throws FabricPipelinerException {
        return DefaultFlowRule.builder()
                .withSelector(selector)
                .withTreatment(mapTreatmentToPiIfNeeded(treatment, tableId))
                .forTable(tableId)
                .makePermanent()
                .withPriority(priority)
                .forDevice(deviceId)
                .fromApp(obj.appId())
                .build();
    }

    TrafficTreatment mapTreatmentToPiIfNeeded(TrafficTreatment treatment, PiTableId tableId)
            throws FabricPipelinerException {
        if (isTreatmentPi(treatment)) {
            return treatment;
        }
        final PiAction piAction;
        try {
            piAction = interpreter.mapTreatment(treatment, tableId);
        } catch (PiPipelineInterpreter.PiInterpreterException ex) {
            throw new FabricPipelinerException(
                    format("Unable to map treatment for table '%s': %s",
                           tableId, ex.getMessage()),
                    ObjectiveError.UNSUPPORTED);
        }
        return DefaultTrafficTreatment.builder()
                .piTableAction(piAction)
                .build();
    }

    private boolean isTreatmentPi(TrafficTreatment treatment) {
        return treatment.allInstructions().size() == 1
                && treatment.allInstructions().get(0).type() == Instruction.Type.PROTOCOL_INDEPENDENT;
    }
}
