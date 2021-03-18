// Copyright 2017-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package org.stratumproject.fabric.tna.behaviour.pipeliner;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Sets;
import org.onlab.packet.MacAddress;
import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flow.criteria.EthCriterion;
import org.onosproject.net.flow.criteria.IPCriterion;
import org.onosproject.net.flow.criteria.MetadataCriterion;
import org.onosproject.net.flow.criteria.MplsCriterion;
import org.onosproject.net.flow.criteria.PiCriterion;
import org.onosproject.net.flow.criteria.VlanIdCriterion;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.net.flowobjective.ObjectiveError;
import org.onosproject.net.pi.model.PiActionId;
import org.onosproject.net.pi.model.PiTableId;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiActionParam;
import org.stratumproject.fabric.tna.behaviour.FabricCapabilities;
import org.stratumproject.fabric.tna.behaviour.P4InfoConstants;

import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static java.lang.String.format;
import static org.stratumproject.fabric.tna.behaviour.Constants.*;
import static org.stratumproject.fabric.tna.behaviour.FabricUtils.criterionNotNull;
import static org.stratumproject.fabric.tna.behaviour.FabricUtils.outputPort;

/**
 * ObjectiveTranslator implementation ForwardingObjective.
 */
class ForwardingObjectiveTranslator
        extends AbstractObjectiveTranslator<ForwardingObjective> {

    //FIXME: Max number supported by PI
    static final int CLONE_TO_CPU_ID = 511;

    private static final Set<Criterion.Type> ACL_CRITERIA = ImmutableSet.of(
            Criterion.Type.IN_PORT,
            Criterion.Type.IN_PHY_PORT,
            Criterion.Type.ETH_DST,
            Criterion.Type.ETH_DST_MASKED,
            Criterion.Type.ETH_SRC,
            Criterion.Type.ETH_SRC_MASKED,
            Criterion.Type.ETH_TYPE,
            Criterion.Type.VLAN_VID,
            Criterion.Type.IP_PROTO,
            Criterion.Type.IPV4_SRC,
            Criterion.Type.IPV4_DST,
            Criterion.Type.TCP_SRC,
            Criterion.Type.TCP_SRC_MASKED,
            Criterion.Type.TCP_DST,
            Criterion.Type.TCP_DST_MASKED,
            Criterion.Type.UDP_SRC,
            Criterion.Type.UDP_SRC_MASKED,
            Criterion.Type.UDP_DST,
            Criterion.Type.UDP_DST_MASKED,
            Criterion.Type.ICMPV4_TYPE,
            Criterion.Type.ICMPV4_CODE,
            Criterion.Type.PROTOCOL_INDEPENDENT);

    private static final Map<PiTableId, PiActionId> NEXT_ID_ACTIONS = ImmutableMap.<PiTableId, PiActionId>builder()
            .put(P4InfoConstants.FABRIC_INGRESS_FORWARDING_BRIDGING,
                 P4InfoConstants.FABRIC_INGRESS_FORWARDING_SET_NEXT_ID_BRIDGING)
            .put(P4InfoConstants.FABRIC_INGRESS_FORWARDING_ROUTING_V4,
                 P4InfoConstants.FABRIC_INGRESS_FORWARDING_SET_NEXT_ID_ROUTING_V4)
            .put(P4InfoConstants.FABRIC_INGRESS_FORWARDING_ROUTING_V6,
                 P4InfoConstants.FABRIC_INGRESS_FORWARDING_SET_NEXT_ID_ROUTING_V6)
            .put(P4InfoConstants.FABRIC_INGRESS_FORWARDING_MPLS,
                 P4InfoConstants.FABRIC_INGRESS_FORWARDING_POP_MPLS_AND_NEXT)
            .put(P4InfoConstants.FABRIC_INGRESS_ACL_ACL,
                 P4InfoConstants.FABRIC_INGRESS_ACL_SET_NEXT_ID_ACL)
            .build();

    ForwardingObjectiveTranslator(DeviceId deviceId, FabricCapabilities capabilities) {
        super(deviceId, capabilities);
    }

    @Override
    public ObjectiveTranslation doTranslate(ForwardingObjective obj)
            throws FabricPipelinerException {
        final ObjectiveTranslation.Builder resultBuilder =
                ObjectiveTranslation.builder();
        switch (obj.flag()) {
            case SPECIFIC:
                processSpecificFwd(obj, resultBuilder);
                break;
            case VERSATILE:
                processVersatileFwd(obj, resultBuilder);
                break;
            case EGRESS:
            default:
                log.warn("Unsupported ForwardingObjective type '{}'", obj.flag());
                return ObjectiveTranslation.ofError(ObjectiveError.UNSUPPORTED);
        }
        return resultBuilder.build();
    }

    private void processVersatileFwd(ForwardingObjective obj,
                                     ObjectiveTranslation.Builder resultBuilder)
            throws FabricPipelinerException {

        final Set<Criterion.Type> unsupportedCriteria = obj.selector().criteria()
                .stream()
                .map(Criterion::type)
                .filter(t -> !ACL_CRITERIA.contains(t))
                .collect(Collectors.toSet());

        if (!unsupportedCriteria.isEmpty()) {
            throw new FabricPipelinerException(format(
                    "unsupported ACL criteria %s", unsupportedCriteria.toString()));
        }

        aclRule(obj, resultBuilder);
    }

    private void processSpecificFwd(ForwardingObjective obj,
                                    ObjectiveTranslation.Builder resultBuilder)
            throws FabricPipelinerException {

        final Set<Criterion> criteriaWithMeta = Sets.newHashSet(obj.selector().criteria());

        // FIXME: Is this really needed? Meta is such an ambiguous field...
        // Why would we match on a META field?
        if (obj.meta() != null) {
            criteriaWithMeta.addAll(obj.meta().criteria());
        }

        final ForwardingFunctionType fft = ForwardingFunctionType.getForwardingFunctionType(obj);

        switch (fft.type()) {
            case UNKNOWN:
                throw new FabricPipelinerException(
                        "unable to detect forwarding function type");
            case L2_UNICAST:
                bridgingRule(obj, criteriaWithMeta, resultBuilder, false);
                break;
            case L2_BROADCAST:
                bridgingRule(obj, criteriaWithMeta, resultBuilder, true);
                break;
            case IPV4_ROUTING:
            case IPV4_ROUTING_MULTICAST:
                ipv4RoutingRule(obj, criteriaWithMeta, resultBuilder);
                break;
            case MPLS_SEGMENT_ROUTING:
                mplsRule(obj, criteriaWithMeta, resultBuilder);
                break;
            case IPV6_ROUTING:
            case IPV6_ROUTING_MULTICAST:
            default:
                throw new FabricPipelinerException(format(
                        "unsupported forwarding function type '%s'",
                        fft));
        }
    }

    private void bridgingRule(ForwardingObjective obj, Set<Criterion> criteriaWithMeta,
                              ObjectiveTranslation.Builder resultBuilder,
                              boolean broadcast)
            throws FabricPipelinerException {

        final VlanIdCriterion vlanIdCriterion = (VlanIdCriterion) criterionNotNull(
                criteriaWithMeta, Criterion.Type.VLAN_VID);
        final TrafficSelector.Builder selector = DefaultTrafficSelector.builder()
                .add(vlanIdCriterion);

        if (!broadcast) {
            final EthCriterion ethDstCriterion = (EthCriterion) criterionNotNull(
                    obj.selector(), Criterion.Type.ETH_DST);
            selector.matchEthDstMasked(ethDstCriterion.mac(), MacAddress.EXACT_MASK);
        }

        resultBuilder.addFlowRule(flowRule(
                obj, P4InfoConstants.FABRIC_INGRESS_FORWARDING_BRIDGING, selector.build()));
    }

    private void ipv4RoutingRule(ForwardingObjective obj, Set<Criterion> criteriaWithMeta,
                                 ObjectiveTranslation.Builder resultBuilder)
            throws FabricPipelinerException {
        final IPCriterion ipDstCriterion = (IPCriterion) criterionNotNull(
                criteriaWithMeta, Criterion.Type.IPV4_DST);

        if (ipDstCriterion.ip().prefixLength() == 0) {
            defaultIpv4Route(obj, resultBuilder);
            return;
        }

        final TrafficSelector selector = DefaultTrafficSelector.builder()
                .add(ipDstCriterion)
                .build();

        resultBuilder.addFlowRule(flowRule(
                obj, P4InfoConstants.FABRIC_INGRESS_FORWARDING_ROUTING_V4, selector));
    }

    private void defaultIpv4Route(ForwardingObjective obj,
                                  ObjectiveTranslation.Builder resultBuilder)
            throws FabricPipelinerException {
        ForwardingObjective defaultObj = obj.copy()
                .withPriority(0)
                .add();
        final TrafficSelector selector = DefaultTrafficSelector.emptySelector();
        resultBuilder.addFlowRule(flowRule(
                defaultObj, P4InfoConstants.FABRIC_INGRESS_FORWARDING_ROUTING_V4, selector));
    }

    private void mplsRule(ForwardingObjective obj, Set<Criterion> criteriaWithMeta,
                          ObjectiveTranslation.Builder resultBuilder)
            throws FabricPipelinerException {

        final MplsCriterion mplsCriterion = (MplsCriterion) criterionNotNull(
                criteriaWithMeta, Criterion.Type.MPLS_LABEL);
        final TrafficSelector selector = DefaultTrafficSelector.builder()
                .add(mplsCriterion)
                .build();

        resultBuilder.addFlowRule(flowRule(
                obj, P4InfoConstants.FABRIC_INGRESS_FORWARDING_MPLS, selector));
    }

    private void aclRule(ForwardingObjective obj,
                         ObjectiveTranslation.Builder resultBuilder)
            throws FabricPipelinerException {
        if (obj.nextId() == null && obj.treatment() != null) {
            final TrafficTreatment treatment = obj.treatment();
            final PortNumber outPort = outputPort(treatment);
            if (outPort != null
                    && outPort.equals(PortNumber.CONTROLLER)
                    && treatment.allInstructions().size() == 1) {

                final PiAction aclAction;
                if (treatment.clearedDeferred()) {
                    aclAction = PiAction.builder()
                            .withId(P4InfoConstants.FABRIC_INGRESS_ACL_PUNT_TO_CPU)
                            .build();
                } else {
                    // Action is COPY_TO_CPU
                    aclAction = PiAction.builder()
                            .withId(P4InfoConstants.FABRIC_INGRESS_ACL_COPY_TO_CPU)
                            .build();
                }
                final TrafficTreatment piTreatment = DefaultTrafficTreatment.builder()
                        .piTableAction(aclAction)
                        .build();
                resultBuilder.addFlowRule(flowRule(
                        obj, P4InfoConstants.FABRIC_INGRESS_ACL_ACL, obj.selector(), piTreatment));
                return;
            }
        }
        TrafficSelector.Builder selectorBuilder = DefaultTrafficSelector.builder(obj.selector());
        // Meta are used to signal if we should match on port_is_edge
        if (obj.meta() != null && obj.meta().getCriterion(Criterion.Type.METADATA) != null) {
            long portType = ((MetadataCriterion) obj.meta().getCriterion(Criterion.Type.METADATA)).metadata();
            // It is a validity bit - 0 or 1
            if (portType == 0 || portType == 1) {
                selectorBuilder.matchPi(PiCriterion.builder()
                        .matchTernary(P4InfoConstants.HDR_PORT_TYPE, portType == 1 ? INFRA : EDGE, 0xffffffff)
                        .build());
            }
        }
        resultBuilder.addFlowRule(flowRule(
                obj, P4InfoConstants.FABRIC_INGRESS_ACL_ACL, selectorBuilder.build()));
    }

    private FlowRule flowRule(
            ForwardingObjective obj, PiTableId tableId, TrafficSelector selector)
            throws FabricPipelinerException {
        return flowRule(obj, tableId, selector, nextIdOrTreatment(obj, tableId));
    }

    private static TrafficTreatment nextIdOrTreatment(
            ForwardingObjective obj, PiTableId tableId)
            throws FabricPipelinerException {
        if (obj.nextId() == null) {
            return obj.treatment();
        } else {
            if (!NEXT_ID_ACTIONS.containsKey(tableId)) {
                throw new FabricPipelinerException(format(
                        "BUG? no next_id action set for table %s", tableId));
            }
            return DefaultTrafficTreatment.builder()
                    .piTableAction(
                            setNextIdAction(obj.nextId(),
                                            NEXT_ID_ACTIONS.get(tableId)))
                    .build();
        }
    }

    private static PiAction setNextIdAction(Integer nextId, PiActionId actionId) {
        final PiActionParam nextIdParam = new PiActionParam(P4InfoConstants.NEXT_ID, nextId);
        return PiAction.builder()
                .withId(actionId)
                .withParameter(nextIdParam)
                .build();
    }
}
