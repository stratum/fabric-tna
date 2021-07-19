// Copyright 2018-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package org.stratumproject.fabric.tna.behaviour;

import org.onlab.util.KryoNamespace;
import org.onosproject.net.PortNumber;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flow.instructions.Instruction;
import org.onosproject.net.flow.instructions.Instructions;
import org.onosproject.net.flow.instructions.L2ModificationInstruction;
import org.onosproject.net.flowobjective.DefaultNextTreatment;
import org.onosproject.net.flowobjective.NextTreatment;
import org.onosproject.net.pi.model.PiPipelineInterpreter;
import org.onosproject.net.pi.model.PiTableId;
import org.onosproject.store.serializers.KryoNamespaces;
import org.stratumproject.fabric.tna.behaviour.pipeliner.FabricPipeliner;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import static com.google.common.base.Preconditions.checkNotNull;
import static java.lang.String.format;

/**
 * Utility class with methods common to fabric-tna pipeconf operations.
 */
public final class FabricUtils {

    public static final KryoNamespace KRYO = new KryoNamespace.Builder()
            .register(KryoNamespaces.API)
            .register(FabricPipeliner.FabricNextGroup.class)
            .build("FabricTnaPipeconf");

    private FabricUtils() {
        // Hides constructor.
    }

    public static Criterion criterion(Collection<Criterion> criteria, Criterion.Type type) {
        return criteria.stream()
                .filter(c -> c.type().equals(type))
                .findFirst().orElse(null);
    }

    public static Criterion criterion(TrafficSelector selector, Criterion.Type type) {
        return selector.getCriterion(type);
    }

    public static Criterion criterionNotNull(TrafficSelector selector, Criterion.Type type) {
        return checkNotNull(criterion(selector, type),
                            format("%s criterion cannot be null", type));
    }

    public static Criterion criterionNotNull(Collection<Criterion> criteria, Criterion.Type type) {
        return checkNotNull(criterion(criteria, type),
                            format("%s criterion cannot be null", type));
    }

    public static Instruction instruction(TrafficTreatment treatment, Instruction.Type type) {
        return treatment.allInstructions()
                .stream()
                .filter(inst -> inst.type() == type)
                .findFirst().orElse(null);
    }

    public static L2ModificationInstruction l2Instruction(
            TrafficTreatment treatment, L2ModificationInstruction.L2SubType subType) {
        return treatment.allInstructions().stream()
                .filter(i -> i.type().equals(Instruction.Type.L2MODIFICATION))
                .map(i -> (L2ModificationInstruction) i)
                .filter(i -> i.subtype().equals(subType))
                .findFirst().orElse(null);
    }

    public static Instruction l2InstructionOrFail(
            TrafficTreatment treatment,
            L2ModificationInstruction.L2SubType subType, PiTableId tableId)
            throws PiPipelineInterpreter.PiInterpreterException {
        final Instruction inst = l2Instruction(treatment, subType);
        if (inst == null) {
            treatmentException(tableId, treatment, format("missing %s instruction", subType));
        }
        return inst;
    }

    public static List<L2ModificationInstruction> l2Instructions(
            TrafficTreatment treatment, L2ModificationInstruction.L2SubType subType) {
        return treatment.allInstructions().stream()
                .filter(i -> i.type().equals(Instruction.Type.L2MODIFICATION))
                .map(i -> (L2ModificationInstruction) i)
                .filter(i -> i.subtype().equals(subType))
                .collect(Collectors.toList());
    }

    public static Instructions.OutputInstruction outputInstruction(TrafficTreatment treatment) {
        return (Instructions.OutputInstruction) instruction(treatment, Instruction.Type.OUTPUT);
    }

    public static PortNumber outputPort(TrafficTreatment treatment) {
        final Instructions.OutputInstruction inst = outputInstruction(treatment);
        return inst == null ? null : inst.port();
    }

    public static PortNumber outputPort(NextTreatment treatment) {
        if (treatment.type() == NextTreatment.Type.TREATMENT) {
            final DefaultNextTreatment t = (DefaultNextTreatment) treatment;
            return outputPort(t.treatment());
        }
        return null;
    }

    public static boolean doCareRangeMatch(long lowerBound, long upperBound, int bitWidth) {
        return lowerBound != 0 || upperBound != (((long) Math.pow(2, bitWidth)) - 1);
    }

    public static void treatmentException(
            PiTableId tableId, TrafficTreatment treatment, String explanation)
            throws PiPipelineInterpreter.PiInterpreterException {
        throw new PiPipelineInterpreter.PiInterpreterException(format(
                "Invalid treatment for table '%s', %s: %s", tableId, explanation, treatment));
    }
}
