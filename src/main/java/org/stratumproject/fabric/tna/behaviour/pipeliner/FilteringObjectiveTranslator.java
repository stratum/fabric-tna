// Copyright 2017-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package org.stratumproject.fabric.tna.behaviour.pipeliner;

import com.google.common.collect.Lists;
import org.onlab.packet.Ethernet;
import org.onlab.packet.MacAddress;
import org.onlab.packet.VlanId;
import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flow.criteria.EthCriterion;
import org.onosproject.net.flow.criteria.PiCriterion;
import org.onosproject.net.flow.criteria.PortCriterion;
import org.onosproject.net.flow.criteria.VlanIdCriterion;
import org.onosproject.net.flow.instructions.Instructions;
import org.onosproject.net.flow.instructions.L2ModificationInstruction.L2SubType;
import org.onosproject.net.flow.instructions.L2ModificationInstruction.ModVlanIdInstruction;
import org.onosproject.net.flowobjective.FilteringObjective;
import org.onosproject.net.flowobjective.Objective;
import org.onosproject.net.flowobjective.ObjectiveError;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiActionParam;
import org.stratumproject.fabric.tna.behaviour.FabricCapabilities;
import org.stratumproject.fabric.tna.behaviour.FabricUtils;
import org.stratumproject.fabric.tna.behaviour.P4InfoConstants;

import java.util.Collection;
import java.util.List;

import static java.lang.String.format;
import static org.onosproject.net.flow.criteria.Criterion.Type.INNER_VLAN_VID;
import static org.onosproject.net.flow.criteria.Criterion.Type.VLAN_VID;
import static org.onosproject.net.flow.instructions.L2ModificationInstruction.L2SubType.VLAN_ID;
import static org.stratumproject.fabric.tna.behaviour.Constants.*;
import static org.stratumproject.fabric.tna.behaviour.FabricUtils.criterion;
import static org.stratumproject.fabric.tna.behaviour.FabricUtils.l2Instruction;

/**
 * ObjectiveTranslator implementation for FilteringObjective.
 */
class FilteringObjectiveTranslator
        extends AbstractObjectiveTranslator<FilteringObjective> {

    private static final PiAction DENY = PiAction.builder()
            .withId(P4InfoConstants.FABRIC_INGRESS_FILTERING_DENY)
            .build();

    private static final int INTERFACE_CONFIG_UPDATE = 2;

    FilteringObjectiveTranslator(DeviceId deviceId, FabricCapabilities capabilities) {
        super(deviceId, capabilities);
    }

    @Override
    public ObjectiveTranslation doTranslate(FilteringObjective obj)
            throws FabricPipelinerException {

        final ObjectiveTranslation.Builder resultBuilder =
                ObjectiveTranslation.builder();

        if (obj.key() == null || obj.key().type() != Criterion.Type.IN_PORT) {
            throw new FabricPipelinerException(
                    format("Unsupported or missing filtering key: key=%s", obj.key()),
                    ObjectiveError.BADPARAMS);
        }

        final PortCriterion inPort = (PortCriterion) obj.key();

        final VlanIdCriterion outerVlan = (VlanIdCriterion) criterion(
                obj.conditions(), Criterion.Type.VLAN_VID);
        final VlanIdCriterion innerVlan = (VlanIdCriterion) criterion(
                obj.conditions(), Criterion.Type.INNER_VLAN_VID);
        final EthCriterion ethDst = (EthCriterion) criterion(
                obj.conditions(), Criterion.Type.ETH_DST);
        final EthCriterion ethDstMasked = (EthCriterion) criterion(
                obj.conditions(), Criterion.Type.ETH_DST_MASKED);

        ingressPortVlanRule(obj, inPort, outerVlan, innerVlan, resultBuilder);
        if (shouldModifyFwdClassifierTable(obj)) {
            fwdClassifierRules(obj, inPort, ethDst, ethDstMasked, resultBuilder);
        } else {
            log.debug("Skipping fwd classifier rules for device {}.", deviceId);
        }
        return resultBuilder.build();
    }

    private boolean shouldModifyFwdClassifierTable(FilteringObjective obj) {
        // NOTE: in fabric pipeline the forwarding classifier acts similarly
        // to the TMAC table of OFDPA that matches on input port.
        // NOTE: that SR signals when it is a port update event by not setting
        // the INTERFACE_CONFIG_UPDATE metadata. During the INTERFACE_CONFIG_UPDATE
        // there is no need to add/remove rules in the fwd_classifier table.
        // NOTE: that in scenarios like (Tagged, Native) -> Tagged where we remove only
        // the native VLAN there is not an ADD following the remove.

        // Forwarding classifier rules should be added/removed to translation when:
        // - the operation is ADD
        //     AND it is a port update event (ADD or UPDATE) OR
        // - it doesn't refer to double tagged traffic
        //     AND it is a port REMOVE event OR
        // - it refers to double tagged traffic
        //     and SR is triggering the removal of forwarding classifier rules.
        return (obj.op() == Objective.Operation.ADD && !isInterfaceConfigUpdate(obj)) ||
                (!isDoubleTagged(obj) && !isInterfaceConfigUpdate(obj)) ||
                (isDoubleTagged(obj) && isLastDoubleTaggedForPort(obj));
    }

    /**
     * Check if the given filtering objective is triggered by a interface config change.
     *
     * @param obj Filtering objective to check.
     * @return True if SR is signaling to not remove the forwarding classifier rule,
     * false otherwise.
     */
    private boolean isInterfaceConfigUpdate(FilteringObjective obj) {
        if (obj.meta() == null) {
            return false;
        }
        Instructions.MetadataInstruction meta = obj.meta().writeMetadata();
        // SR is setting this metadata when an interface config update has
        // been performed and thus fwd classifier rules should not be removed
        return (meta != null && (meta.metadata() & meta.metadataMask()) == INTERFACE_CONFIG_UPDATE);
    }

    /**
     * Check if the given filtering objective is the last filtering objective
     * for a double-tagged host for a specific port.
     * <p>
     * {@see org.onosproject.segmentrouting.RoutingRulePopulator#buildDoubleTaggedFilteringObj()}
     * {@see org.onosproject.segmentrouting.RoutingRulePopulator#processDoubleTaggedFilter()}
     *
     * @param obj Filtering objective to check.
     * @return True if SR is signaling to remove the forwarding classifier rule,
     * false otherwise.
     */
    private boolean isLastDoubleTaggedForPort(FilteringObjective obj) {
        Instructions.MetadataInstruction meta = obj.meta().writeMetadata();
        // SR is setting this metadata when a double tagged filtering objective
        // is removed and no other hosts is sharing the same input port.
        return (meta != null && (meta.metadata() & meta.metadataMask()) == 1);
    }

    private boolean isDoubleTagged(FilteringObjective obj) {
        return obj.meta() != null &&
                FabricUtils.l2Instruction(obj.meta(), L2SubType.VLAN_POP) != null &&
                FabricUtils.criterion(obj.conditions(), VLAN_VID) != null &&
                FabricUtils.criterion(obj.conditions(), INNER_VLAN_VID) != null;
    }

    private void ingressPortVlanRule(
            FilteringObjective obj,
            Criterion inPortCriterion,
            VlanIdCriterion outerVlanCriterion,
            VlanIdCriterion innerVlanCriterion,
            ObjectiveTranslation.Builder resultBuilder)
            throws FabricPipelinerException {

        final boolean outerVlanValid = outerVlanCriterion != null
                && !outerVlanCriterion.vlanId().equals(VlanId.NONE);
        final boolean innerVlanValid = innerVlanCriterion != null
                && !innerVlanCriterion.vlanId().equals(VlanId.NONE);

        if (innerVlanValid && !capabilities.supportDoubleVlanTerm()) {
            throw new FabricPipelinerException(
                    "Found 2 VLAN IDs, but the pipeline does not support double VLAN termination",
                    ObjectiveError.UNSUPPORTED);
        }

        final PiCriterion piCriterion = PiCriterion.builder()
                .matchExact(P4InfoConstants.HDR_VLAN_IS_VALID, outerVlanValid ? ONE : ZERO)
                .build();

        final TrafficSelector.Builder selector = DefaultTrafficSelector.builder()
                .add(inPortCriterion)
                .add(piCriterion);
        if (outerVlanValid) {
            selector.add(outerVlanCriterion);
        }
        if (innerVlanValid) {
            selector.add(innerVlanCriterion);
        }

        final TrafficTreatment.Builder treatmentBuilder;
        if (obj.type().equals(FilteringObjective.Type.DENY)) {
            treatmentBuilder = DefaultTrafficTreatment.builder()
                    .piTableAction(DENY);
        } else {
            treatmentBuilder = obj.meta() == null
                    ? DefaultTrafficTreatment.builder() : DefaultTrafficTreatment.builder(obj.meta());
            // FIXME Remove once AETHER-1404 has been implemented
            // Infrastructure ports are tagged due to the PW transport vlan (4090). Otherwise,
            // check if the vlan being pushed is the default internal vlan (4094).
            if (!innerVlanValid && outerVlanValid &&
                    outerVlanCriterion.vlanId().equals(VlanId.vlanId((short) DEFAULT_PW_TRANSPORT_VLAN))) {
                treatmentBuilder.writeMetadata(IS_INFRA_PORT, METADATA_MASK);
            } else if (obj.meta() != null) {
                ModVlanIdInstruction modVlanIdInstruction = (ModVlanIdInstruction) l2Instruction(obj.meta(), VLAN_ID);
                if (modVlanIdInstruction != null && modVlanIdInstruction.vlanId().toShort() == DEFAULT_VLAN) {
                    treatmentBuilder.writeMetadata(IS_INFRA_PORT, METADATA_MASK);
                }
            }
        }

        resultBuilder.addFlowRule(flowRule(
                obj, P4InfoConstants.FABRIC_INGRESS_FILTERING_INGRESS_PORT_VLAN,
                selector.build(), treatmentBuilder.build()));
    }

    private void fwdClassifierRules(
            FilteringObjective obj,
            PortCriterion inPortCriterion,
            EthCriterion ethDstCriterion,
            EthCriterion ethDstMaskedCriterion,
            ObjectiveTranslation.Builder resultBuilder)
            throws FabricPipelinerException {

        final List<FlowRule> flowRules = Lists.newArrayList();

        final PortNumber inPort = inPortCriterion.port();
        if (ethDstCriterion == null) {
            if (ethDstMaskedCriterion == null) {
                // No match. Do bridging (default action).
                return;
            }
            // Masked fwd classifier rule
            final MacAddress dstMac = ethDstMaskedCriterion.mac();
            final MacAddress dstMacMask = ethDstMaskedCriterion.mask();
            flowRules.add(maskedFwdClassifierRule(inPort, dstMac, dstMacMask, obj));
        } else {
            final MacAddress dstMac = ethDstCriterion.mac();
            flowRules.addAll(ipFwdClassifierRules(inPort, dstMac, obj));
            flowRules.addAll(mplsFwdClassifierRules(inPort, dstMac, obj));
        }

        for (FlowRule f : flowRules) {
            resultBuilder.addFlowRule(f);
        }
    }

    private FlowRule maskedFwdClassifierRule(
            PortNumber inPort, MacAddress dstMac, MacAddress dstMacMask,
            FilteringObjective obj)
            throws FabricPipelinerException {
        final TrafficTreatment treatment;
        final short ethType;
        if (dstMac.equals(MacAddress.IPV4_MULTICAST)
                && dstMacMask.equals(MacAddress.IPV4_MULTICAST_MASK)) {
            treatment = fwdClassifierTreatment(FWD_IPV4_ROUTING);
            ethType = Ethernet.TYPE_IPV4;
        } else if (dstMac.equals(MacAddress.IPV6_MULTICAST)
                && dstMacMask.equals(MacAddress.IPV6_MULTICAST_MASK)) {
            treatment = fwdClassifierTreatment(FWD_IPV6_ROUTING);
            ethType = Ethernet.TYPE_IPV6;
        } else {
            throw new FabricPipelinerException(format(
                    "Unsupported masked Ethernet address for fwd " +
                            "classifier rule (mac=%s, mask=%s)",
                    dstMac, dstMacMask));
        }
        return fwdClassifierRule(inPort, ethType, dstMac, dstMacMask, treatment, obj);
    }

    private Collection<FlowRule> ipFwdClassifierRules(
            PortNumber inPort, MacAddress dstMac, FilteringObjective obj)
            throws FabricPipelinerException {
        final Collection<FlowRule> flowRules = Lists.newArrayList();
        flowRules.add(fwdClassifierRule(
                inPort, Ethernet.TYPE_IPV4, dstMac, null,
                fwdClassifierTreatment(FWD_IPV4_ROUTING), obj));
        flowRules.add(fwdClassifierRule(
                inPort, Ethernet.TYPE_IPV6, dstMac, null,
                fwdClassifierTreatment(FWD_IPV6_ROUTING), obj));
        return flowRules;
    }

    private Collection<FlowRule> mplsFwdClassifierRules(
            PortNumber inPort, MacAddress dstMac, FilteringObjective obj)
            throws FabricPipelinerException {
        // Forwarding classifier for MPLS is composed of 2 rules
        // with higher priority wrt standard forwarding classifier rules,
        // this is due to overlap on ternary matching.
        TrafficTreatment treatment = fwdClassifierTreatment(FWD_MPLS);
        final PiCriterion ethTypeMplsIpv4 = PiCriterion.builder()
                .matchTernary(P4InfoConstants.HDR_ETH_TYPE,
                              Ethernet.MPLS_UNICAST, ETH_TYPE_EXACT_MASK)
                .matchExact(P4InfoConstants.HDR_IP_ETH_TYPE,
                            Ethernet.TYPE_IPV4)
                .build();
        final TrafficSelector selectorMplsIpv4 = DefaultTrafficSelector.builder()
                .matchInPort(inPort)
                .matchPi(ethTypeMplsIpv4)
                .matchEthDstMasked(dstMac, MacAddress.EXACT_MASK)
                .build();

        final PiCriterion ethTypeMplsIpv6 = PiCriterion.builder()
                .matchTernary(P4InfoConstants.HDR_ETH_TYPE,
                              Ethernet.MPLS_UNICAST, ETH_TYPE_EXACT_MASK)
                .matchExact(P4InfoConstants.HDR_IP_ETH_TYPE,
                            Ethernet.TYPE_IPV6)
                .build();
        final TrafficSelector selectorMplsIpv6 = DefaultTrafficSelector.builder()
                .matchInPort(inPort)
                .matchPi(ethTypeMplsIpv6)
                .matchEthDstMasked(dstMac, MacAddress.EXACT_MASK)
                .build();

        return List.of(
                flowRule(obj, P4InfoConstants.FABRIC_INGRESS_FILTERING_FWD_CLASSIFIER,
                         selectorMplsIpv4, treatment, obj.priority() + 1),
                flowRule(obj, P4InfoConstants.FABRIC_INGRESS_FILTERING_FWD_CLASSIFIER,
                         selectorMplsIpv6, treatment, obj.priority() + 1)
        );
    }

    private FlowRule fwdClassifierRule(
            PortNumber inPort, short ethType, MacAddress dstMac, MacAddress dstMacMask,
            TrafficTreatment treatment, FilteringObjective obj)
            throws FabricPipelinerException {
        // Match on ip_eth_type that is the eth_type of the L3 protocol.
        // i.e., if the packet has an IP header, ip_eth_type should
        // contain the corresponding eth_type (for IPv4 or IPv6)
        final PiCriterion ethTypeCriterion = PiCriterion.builder()
                .matchExact(P4InfoConstants.HDR_IP_ETH_TYPE, ethType)
                .build();
        final TrafficSelector selector = DefaultTrafficSelector.builder()
                .matchInPort(inPort)
                .matchPi(ethTypeCriterion)
                .matchEthDstMasked(dstMac, dstMacMask == null
                        ? MacAddress.EXACT_MASK : dstMacMask)
                .build();
        return flowRule(
                obj, P4InfoConstants.FABRIC_INGRESS_FILTERING_FWD_CLASSIFIER,
                selector, treatment);
    }

    private TrafficTreatment fwdClassifierTreatment(byte fwdType) {
        final PiActionParam param = new PiActionParam(P4InfoConstants.FWD_TYPE, fwdType);
        final PiAction action = PiAction.builder()
                .withId(P4InfoConstants.FABRIC_INGRESS_FILTERING_SET_FORWARDING_TYPE)
                .withParameter(param)
                .build();
        return DefaultTrafficTreatment.builder()
                .piTableAction(action)
                .build();

    }
}
