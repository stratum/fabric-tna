// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package org.stratumproject.fabric.tna.behaviour.traceable;

import com.google.common.collect.Lists;
import org.onlab.packet.MacAddress;
import org.onlab.packet.VlanId;
import org.onlab.util.ImmutableByteSequence;
import org.onosproject.core.GroupId;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DataPlaneEntity;
import org.onosproject.net.PipelineTraceableHitChain;
import org.onosproject.net.PipelineTraceableInput;
import org.onosproject.net.PipelineTraceableOutput;
import org.onosproject.net.PipelineTraceableOutput.PipelineTraceableResult;
import org.onosproject.net.PipelineTraceablePacket;
import org.onosproject.net.PortNumber;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flow.criteria.VlanIdCriterion;
import org.onosproject.net.group.Group;
import org.onosproject.net.group.GroupDescription;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiActionParam;
import org.onosproject.net.pi.runtime.PiActionProfileGroup;
import org.onosproject.net.pi.runtime.PiMulticastGroupEntry;
import org.onosproject.net.pi.runtime.PiPreEntry;
import org.onosproject.net.pi.runtime.PiPreEntryType;
import org.onosproject.net.pi.runtime.PiPreReplica;
import org.onosproject.net.pi.service.PiTranslationException;
import org.onosproject.net.pi.service.PiTranslationService;
import org.stratumproject.fabric.tna.behaviour.FabricCapabilities;
import org.stratumproject.fabric.tna.behaviour.P4InfoConstants;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.stratumproject.fabric.tna.behaviour.FabricUtils.criterion;

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

        // Update the meta using the packet information.
        // Emulate partially the job done by the parser
        FabricTraceableMetadata metadata = updateMetadata(input.ingressPacket(), metadataBuilder);
        PipelineTraceablePacket egressPacket = new PipelineTraceablePacket(
                input.ingressPacket().packet(), metadata);

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
            outputBuilder.appendToLog(ctrlOutput.log());
            // Error - exit immediately without updating the hit chain
            if (ctrlOutput.hitChains().size() != 1) {
                return outputBuilder.appendToLog("Too many hit chains. Aborting")
                        .dropped()
                        .addHitChain(currentHitChain)
                        .build();
            }
            ctrlOutput.hitChains().get(0).hitChain().forEach(currentHitChain::addDataPlaneEntity);
            currentHitChain.setEgressPacket(ctrlOutput.hitChains().get(0).egressPacket());
            // Did not end well - exit
            if (ctrlOutput.result() != PipelineTraceableResult.SUCCESS) {
                return outputBuilder.setResult(ctrlOutput.result())
                        .addHitChain(currentHitChain)
                        .build();
            }
            // Finally refresh the ctrl input before jumping to the next ctrl block
            ctrlInput = new PipelineTraceableInput(currentHitChain.egressPacket(), input.ingressPort(),
                    input.deviceState());
        }

        // After ingress processing, we handle the output to controller scenarios.
        // Note this is a simplification of the real processing.
        FabricTraceableMetadata traceableMetadata = getMetadata(currentHitChain.egressPacket()).build();
        PipelineTraceableHitChain controllerHitChain = handlePacketToController(currentHitChain, outputBuilder);
        if (controllerHitChain != null) {
            outputBuilder.addHitChain(controllerHitChain);
            // Done! No need to go further in this case.
            if (traceableMetadata.isPuntToController()) {
                return outputBuilder.addHitChain(controllerHitChain)
                        .build();
            }
        }

        // In the remaining cases, including the copy to controller we have to process the group
        // and go through the egress control block.
        List<PipelineTraceableHitChain> doneHitChains = handleGroup(input.ingressPort(), input.groups(),
                currentHitChain, outputBuilder);
        // If all the hit chains have been blocked - do not proceed
        List<PipelineTraceableHitChain> passedHitChains = doneHitChains.stream()
                .filter(hitChain -> !hitChain.isDropped())
                .collect(Collectors.toList());
        // Save the blocked chains
        doneHitChains.stream()
                .filter(hitchain -> !passedHitChains.contains(hitchain))
                .forEach(outputBuilder::addHitChain);
        // Hit chain has been already saved, set a message, then exit
        if (controllerHitChain == null && passedHitChains.isEmpty()) {
            return outputBuilder.appendToLog("Packet has no output in device " + deviceId + ". Dropping")
                    .dropped()
                    .build();
        }

        // Finally, here happens the egress handling where we have to manage
        // all the copies of the packet. We need to set the egress port in the meta
        List<PipelineTraceableHitChain> egressHitchains = Lists.newArrayList();
        boolean passed;
        for (PipelineTraceableHitChain passedHitChain : passedHitChains) {
            traceableMetadata = getMetadata(passedHitChain.egressPacket())
                .setOutPort(passedHitChain.outputPort().port())
                .build();
            egressPacket = new PipelineTraceablePacket(passedHitChain.egressPacket().packet(),
                traceableMetadata);
            ctrlInput = new PipelineTraceableInput(egressPacket, input.ingressPort(), input.deviceState());
            passed = true;
            for (PipelineTraceableCtrl traceableCtrl : this.egressPipeline) {
                if (log.isDebugEnabled()) {
                    log.debug("Packet enters {}", traceableCtrl.getClass().getSimpleName());
                }
                ctrlOutput = traceableCtrl.apply(ctrlInput);
                // Cannot be null
                if (ctrlOutput == null) {
                    passedHitChain.dropped();
                    outputBuilder.appendToLog("No traceable output. Aborting")
                        .addHitChain(passedHitChain);
                    passed = false;
                    break;
                }
                // Stores log and update current hit chain
                outputBuilder.appendToLog(ctrlOutput.log());
                // Error - exit immediately without updating the hit chain
                if (ctrlOutput.hitChains().size() != 1) {
                    passedHitChain.dropped();
                    outputBuilder.appendToLog("Too many hit chains. Aborting")
                        .addHitChain(passedHitChain);
                    passed = false;
                    break;
                }
                ctrlOutput.hitChains().get(0).hitChain().forEach(passedHitChain::addDataPlaneEntity);
                passedHitChain.setEgressPacket(ctrlOutput.hitChains().get(0).egressPacket());
                // Did not end well - exit
                if (ctrlOutput.result() != PipelineTraceableResult.SUCCESS) {
                    passedHitChain.dropped();
                    outputBuilder.appendToLog("Dropped. Aborting")
                        .addHitChain(passedHitChain);
                    passed = false;
                    break;
                }
                // Finally refresh the ctrl input before jumping to the next ctrl block
                ctrlInput = new PipelineTraceableInput(passedHitChain.egressPacket(), input.ingressPort(),
                    input.deviceState());
            }
            // Was not dropped
            if (passed) {
                outputBuilder.addHitChain(passedHitChain);
                egressHitchains.add(passedHitChain);
            }
        }

        // Hit chain has been already saved, set a message, then exit
        if (controllerHitChain == null && egressHitchains.isEmpty()) {
            return outputBuilder.appendToLog("Packet has no output in device " + deviceId + ". Dropping")
                    .dropped()
                    .build();
        }

        return outputBuilder.build();
    }

    // Handle output to controller scenarios
    private PipelineTraceableHitChain handlePacketToController(PipelineTraceableHitChain currentHitChain,
                                             PipelineTraceableOutput.Builder outputBuilder) {
        FabricTraceableMetadata traceableMetadata = getMetadata(currentHitChain.egressPacket()).build();
        // Invalid scenario - exit immediately
        if (!traceableMetadata.isPuntToController() && !traceableMetadata.isCopyToController()) {
            if (log.isDebugEnabled()) {
                log.debug("There is no output to controller - skipped");
            }
            return null;
        }
        ConnectPoint controllerPort = new ConnectPoint(deviceId, PortNumber.CONTROLLER);
        return buildOutputFromDevice(currentHitChain, null, controllerPort, false);
    }

    // Builds a possible output from this device
    private PipelineTraceableHitChain buildOutputFromDevice(PipelineTraceableHitChain currentHitChain,
                                                            PipelineTraceablePacket currentPacket,
                                                            ConnectPoint outputPort,
                                                            boolean dropped) {
        // Use packet stored in the hitchain
        if (currentPacket == null) {
            TrafficSelector egressSelector = DefaultTrafficSelector.builder(currentHitChain.egressPacket().packet())
                    .build();
            FabricTraceableMetadata egressMetadata = getMetadata(currentHitChain.egressPacket())
                    .build();
            currentPacket = new PipelineTraceablePacket(egressSelector, egressMetadata);
        }
        // Create the final hit chain from the current one (deep copy)
        PipelineTraceableHitChain finalHitChain = new PipelineTraceableHitChain(outputPort,
                Lists.newArrayList(currentHitChain.hitChain()),
                currentPacket);
        // Dropped early
        if (!dropped) {
            finalHitChain.pass();
        } else if (log.isDebugEnabled()) {
            log.debug("Packet {} has been dropped", currentPacket);
        }
        return finalHitChain;
    }

    private List<PipelineTraceableHitChain> handleGroup(ConnectPoint inputPort,
                                                        Map<GroupId, Group> groups,
                                                        PipelineTraceableHitChain currentHitChain,
                                                        PipelineTraceableOutput.Builder outputBuilder) {
        FabricTraceableMetadata metadata = (FabricTraceableMetadata) currentHitChain.egressPacket().metadata();
        // First step is to retrieve the group
        Group group = groups.get(metadata.getGroupId());

        // Group does not exist in the dataplane
        if (group == null) {
            if (log.isDebugEnabled()) {
                log.debug("Group {} is null", metadata.getGroupId());
            }
            currentHitChain.dropped();
            outputBuilder.appendToLog("Null group for groupId " + metadata.getGroupId())
                    .noGroups()
                    .addHitChain(currentHitChain);
            return Collections.emptyList();
        }

        if (log.isDebugEnabled()) {
            log.debug("Analyzing group {}", group.id());
        }

        // Group is there but there are no members/buckets
        // Add the group to before exiting (it is not done before)
        if (group.buckets().buckets().size() == 0) {
            if (log.isDebugEnabled()) {
                log.debug("Group {} has no buckets", group.id());
            }
            currentHitChain.addDataPlaneEntity(new DataPlaneEntity(group));
            currentHitChain.dropped();
            outputBuilder.appendToLog("Group " + group.id() + " has no buckets")
                    .noMembers()
                    .addHitChain(currentHitChain);
            return Collections.emptyList();
        }

        // Handle group based on type.
        try {
            if (group.type() == GroupDescription.Type.ALL) {
                if (log.isDebugEnabled()) {
                    log.debug("Handling Multicast group {}", group);
                }
                return handleMcastGroup(inputPort, group, currentHitChain, outputBuilder);
            } else if (group.type() == GroupDescription.Type.SELECT) {
                if (log.isDebugEnabled()) {
                    log.debug("Handling ECMP group {}", group);
                }
                return handleEcmpGroup(group, currentHitChain, outputBuilder);
            }
            // Generic error - group is not supported
            if (log.isDebugEnabled()) {
                log.debug("Group {} is not yet supported", group.type());
            }
        } catch (PiTranslationException e) {
            log.debug("handleGroup failed due to PI translation error: {}", e.getMessage());
        }
        currentHitChain.dropped();
        outputBuilder.appendToLog("Group " + group.id() + " is not supported")
                .dropped()
                .addHitChain(currentHitChain);
        return Collections.emptyList();
    }

    private List<PipelineTraceableHitChain> handleMcastGroup(ConnectPoint inputPort, Group mcastGroup,
                                                             PipelineTraceableHitChain currentHitChain,
                                                             PipelineTraceableOutput.Builder outputBuilder)
            throws PiTranslationException {
        // Init steps
        FabricTraceableMetadata traceableMetadata = getMetadata(currentHitChain.egressPacket()).build();

        // First we do the translation and then we handle the buckets one by one
        PiTranslationService piTranslationService = this.handler().get(PiTranslationService.class);
        PiPreEntry preEntry = piTranslationService.replicationGroupTranslator().translate(mcastGroup, pipeconf);

        // Double check - but it should not be needed at this point
        if (preEntry.preEntryType() != PiPreEntryType.MULTICAST_GROUP) {
            if (log.isDebugEnabled()) {
                log.debug("PreEntry {} is not yet supported", preEntry.preEntryType());
            }
            currentHitChain.dropped();
            outputBuilder.appendToLog("PreEntry " + preEntry.preEntryType() + " is not supported")
                    .dropped()
                    .addHitChain(currentHitChain);
            return Collections.emptyList();
        }
        PiMulticastGroupEntry multicastGroupEntry = (PiMulticastGroupEntry) preEntry;
        if (multicastGroupEntry.replicas().isEmpty()) {
            if (log.isDebugEnabled()) {
                log.debug("MulticastGroupEntry {} has no replicas", multicastGroupEntry.groupId());
            }
            currentHitChain.dropped();
            outputBuilder.appendToLog("MulticastGroupEntry {} " + multicastGroupEntry.groupId() +
                    " has no replicas")
                    .noMembers()
                    .addHitChain(currentHitChain);
            return Collections.emptyList();
        }

        ConnectPoint outputPort;
        List<PipelineTraceableHitChain> newHitChains = Lists.newArrayList();
        // Cycle in each of the group's replica and build output from device
        for (PiPreReplica preReplica : multicastGroupEntry.replicas()) {
            // Add the group to the traversed groups and build output from device
            currentHitChain.addDataPlaneEntity(new DataPlaneEntity(mcastGroup));
            outputPort = new ConnectPoint(deviceId, preReplica.egressPort());
            // We handle here also the prune of the ingress port
            newHitChains.add(buildOutputFromDevice(currentHitChain, null, outputPort,
                    traceableMetadata.isMulticast() && inputPort.equals(outputPort)));
        }
        return newHitChains;
    }

    private List<PipelineTraceableHitChain> handleEcmpGroup(Group ecmpGroup,
                                                            PipelineTraceableHitChain currentHitChain,
                                                            PipelineTraceableOutput.Builder outputBuilder)
            throws PiTranslationException {
        // Translate as action profile group and then handle the members one by one
        PiTranslationService piTranslationService = this.handler().get(PiTranslationService.class);
        PiActionProfileGroup actionProfileGroup = piTranslationService.groupTranslator().translate(
                ecmpGroup, pipeconf);

        // Double check on the members - but it should not be needed at this point
        if (actionProfileGroup.members().isEmpty()) {
            if (log.isDebugEnabled()) {
                log.debug("ActionProfileGroup {} has no members", actionProfileGroup.actionProfile());
            }
            currentHitChain.dropped();
            outputBuilder.appendToLog("ActionProfileGroup {} " + actionProfileGroup.actionProfile() +
                    " has no members")
                    .noMembers()
                    .addHitChain(currentHitChain);
            return Collections.emptyList();
        }

        ConnectPoint outputPort;
        List<PipelineTraceableHitChain> newHitChains = Lists.newArrayList();
        PipelineTraceablePacket newPacket;
        // Cycle on each valid member updating first the packet (both the traffic selector
        // and the metadata). Then, builds out the output from device
        for (PiActionProfileGroup.WeightedMember weightedMember : actionProfileGroup.members()) {
            currentHitChain.addDataPlaneEntity(new DataPlaneEntity(ecmpGroup));
            newPacket = updatePacket(currentHitChain.egressPacket(), weightedMember.instance().action());
            outputPort = new ConnectPoint(deviceId, PortNumber.portNumber(getOutputFromParams(
                    weightedMember.instance().action().parameters())));
            newHitChains.add(buildOutputFromDevice(currentHitChain, newPacket, outputPort, false));
        }
        return newHitChains;
    }

    // Update packet by acting on the traffic selector and metadata
    private PipelineTraceablePacket updatePacket(PipelineTraceablePacket currentPacket,
                                                 PiAction action) {
        TrafficSelector.Builder newSelector = DefaultTrafficSelector.builder(currentPacket.packet());
        FabricTraceableMetadata.Builder newMetadata = getMetadata(currentPacket);
        for (PiActionParam piActionParam : action.parameters()) {
            if (piActionParam.id().equals(P4InfoConstants.SMAC)) {
                if (log.isDebugEnabled()) {
                    log.debug("Rewriting SOURCE_MAC");
                }
                byte[] mac = piActionParam.value()
                        .asArray();
                newSelector.matchEthSrc(MacAddress.valueOf(mac));
            } else if (piActionParam.id().equals(P4InfoConstants.DMAC)) {
                if (log.isDebugEnabled()) {
                    log.debug("Rewriting DST_MAC");
                }
                byte[] mac = piActionParam.value()
                        .asArray();
                newSelector.matchEthDst(MacAddress.valueOf(mac));
            } else if (piActionParam.id().equals(P4InfoConstants.LABEL)) {
                if (log.isDebugEnabled()) {
                    log.debug("Setting MPLS_LABEL");
                }
                newMetadata.setMplsLabel(getMplsLabelFromParam(piActionParam));
            } else if (!piActionParam.id().equals(P4InfoConstants.PORT_NUM)) {
                if (log.isDebugEnabled()) {
                    log.debug("Parameter {} is not yet supported", piActionParam.id());
                }
            }
        }
        return new PipelineTraceablePacket(newSelector.build(), newMetadata.build());
    }

    // Update the meta by loading hdr data
    private FabricTraceableMetadata updateMetadata(PipelineTraceablePacket currentPacket,
                                                   FabricTraceableMetadata.Builder metaBuilder) {
        final VlanIdCriterion vlanCriterion = (VlanIdCriterion) criterion(
                currentPacket.packet().criteria(), Criterion.Type.VLAN_VID);
        if (vlanCriterion != null && !vlanCriterion.vlanId().equals(VlanId.NONE)) {
            metaBuilder.setVlanId(vlanCriterion.vlanId().toShort());
        }
        return metaBuilder.build();
    }

    private long getOutputFromParams(Collection<PiActionParam> params) {
        long portNumber;
        try {
            portNumber = params.stream()
                    .filter(param -> param.id().equals(P4InfoConstants.PORT_NUM))
                    .findFirst()
                    .orElse(new PiActionParam(P4InfoConstants.PORT_NUM, 0))
                    .value()
                    .fit(Long.SIZE)
                    .asReadOnlyBuffer()
                    .getLong();
        } catch (ImmutableByteSequence.ByteSequenceTrimException e) {
            log.debug("getOutputFromParams failed due to trim error: {}", e.getMessage());
            portNumber = 0;
        }
        return portNumber;
    }

    private int getMplsLabelFromParam(PiActionParam param) {
        int mplsLabel;
        try {
            mplsLabel = param.value()
                    .fit(Integer.SIZE)
                    .asReadOnlyBuffer()
                    .getInt();
        } catch (ImmutableByteSequence.ByteSequenceTrimException e) {
            log.debug("getMplsLabelFromParams failed due to trim error: {}", e.getMessage());
            mplsLabel = -1;
        }
        return mplsLabel;
    }

}
