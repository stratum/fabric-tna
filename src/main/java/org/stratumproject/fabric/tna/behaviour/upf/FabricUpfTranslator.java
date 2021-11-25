// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.behaviour.upf;

import com.google.common.collect.BiMap;
import com.google.common.collect.ImmutableBiMap;
import org.apache.commons.lang3.tuple.Pair;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.Ip4Prefix;
import org.onlab.util.ImmutableByteSequence;
import org.onosproject.core.ApplicationId;
import org.onosproject.net.DeviceId;
import org.onosproject.net.behaviour.upf.UpfInterface;
import org.onosproject.net.behaviour.upf.UpfProgrammableException;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.criteria.PiCriterion;
import org.onosproject.net.pi.model.PiActionId;
import org.onosproject.net.pi.model.PiTableId;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiActionParam;
import org.onosproject.net.pi.runtime.PiTableAction;

import java.util.Arrays;

import static java.lang.String.format;
import static org.stratumproject.fabric.tna.behaviour.Constants.DEFAULT_SLICE_ID;
import static org.stratumproject.fabric.tna.behaviour.Constants.TC_BEST_EFFORT;
import static org.stratumproject.fabric.tna.behaviour.Constants.TC_CONTROL;
import static org.stratumproject.fabric.tna.behaviour.Constants.TC_ELASTIC;
import static org.stratumproject.fabric.tna.behaviour.Constants.TC_REAL_TIME;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.*;

/**
 * Provides logic to translate UPF entities into pipeline-specific ones and vice-versa.
 * Implementation should be stateless, with all state delegated to FabricUpfStore.
 */
public class FabricUpfTranslator {

    // TODO: agree on a mapping with the PFCP agent
    //  Make sure to have a 1 to 1 mapping between QFI and TC.
    static final BiMap<Byte, Integer> QFI_TO_TC = ImmutableBiMap.of(
            // FIXME: allow explicit QFI mapping to Best-Effort. Currently,
            //  the only way the mobile core can set Best-Effort is by not
            //  specifying a QFI in PDRs. We do this to maintain backward
            //  compatibility with PFCP Agent, but eventually all PDRs will have
            //  a QFI.
            // (byte) 0, TC_BEST_EFFORT, --> Used for PDRs without QFI
            (byte) 1, TC_CONTROL,
            (byte) 2, TC_REAL_TIME,
            (byte) 3, TC_ELASTIC);

    /**
     * Returns true if the given table entry is a UE Session rule from the physical fabric pipeline, and
     * false otherwise.
     *
     * @param entry the entry that may or may not be a fabric.p4 UE Session rule
     * @return true if the entry is a fabric.p4 UE Session rule
     */
    public boolean isFabricUeSessionRule(FlowRule entry) {
        return entry.table().equals(FABRIC_INGRESS_SPGW_UPLINK_SESSIONS)
                || entry.table().equals(FABRIC_INGRESS_SPGW_DOWNLINK_SESSIONS);
    }

    /**
     * Returns true if the given table entry is a UPF Termination rule from the physical fabric pipeline, and
     * false otherwise.
     *
     * @param entry the entry that may or may not be a fabric.p4 UPF Termination rule
     * @return true if the entry is a fabric.p4 UPF Termination rule
     */
    public boolean isFabricUpfTerminationRule(FlowRule entry) {
        return entry.table().equals(FABRIC_INGRESS_SPGW_UPLINK_TERMINATIONS)
                || entry.table().equals(FABRIC_INGRESS_SPGW_DOWNLINK_TERMINATIONS);
    }

    /**
     * Returns true if the given table entry is an interface table entry from the fabric.p4 physical pipeline, and
     * false otherwise.
     *
     * @param entry the entry that may or may not be a fabric.p4 UPF interface
     * @return true if the entry is a fabric.p4 UPF interface
     */
    public boolean isFabricInterface(FlowRule entry) {
        return entry.table().equals(FABRIC_INGRESS_SPGW_INTERFACES);
    }

    /**
     * Translate a fabric.p4 interface table entry to a UpfInterface instance for easier handling.
     *
     * @param entry the fabric.p4 entry to translate
     * @return the corresponding UpfInterface
     * @throws UpfProgrammableException if the entry cannot be translated
     */
    public UpfInterface fabricEntryToInterface(FlowRule entry)
            throws UpfProgrammableException {
        Pair<PiCriterion, PiTableAction> matchActionPair = FabricUpfTranslatorUtil.fabricEntryToPiPair(entry);
        PiCriterion match = matchActionPair.getLeft();
        PiAction action = (PiAction) matchActionPair.getRight();

        var ifaceBuilder = UpfInterface.builder()
                .setPrefix(FabricUpfTranslatorUtil.getFieldPrefix(match, HDR_IPV4_DST_ADDR));

        if (action.id().equals(FABRIC_INGRESS_SPGW_IFACE_ACCESS)) {
            ifaceBuilder.setAccess();
        } else if (action.id().equals(FABRIC_INGRESS_SPGW_IFACE_CORE)) {
            ifaceBuilder.setCore();
        } else if (action.id().equals(FABRIC_INGRESS_SPGW_IFACE_DBUF)) {
            ifaceBuilder.setDbufReceiver();
        } else {
            throw new UpfProgrammableException("Invalid action ID");
        }

        return ifaceBuilder.build();
    }

    /**
     * Translate a UpfInterface to a FlowRule to be inserted into the fabric.p4 pipeline.
     *
     * @param upfInterface The interface to be translated
     * @param deviceId     the ID of the device the FlowRule should be installed on
     * @param appId        the ID of the application that will insert the FlowRule
     * @param priority     the FlowRule's priority
     * @return the UPF interface translated to a FlowRule
     * @throws UpfProgrammableException if the interface cannot be translated
     */
    public FlowRule interfaceToFabricEntry(UpfInterface upfInterface, DeviceId deviceId,
                                           ApplicationId appId, int priority) throws UpfProgrammableException {
        int interfaceTypeInt;
        int gtpuValidity;
        PiActionId actionId;
        if (upfInterface.isDbufReceiver()) {
            actionId = FABRIC_INGRESS_SPGW_IFACE_DBUF;
            gtpuValidity = 1;
        } else if (upfInterface.isAccess()) {
            actionId = FABRIC_INGRESS_SPGW_IFACE_ACCESS;
            gtpuValidity = 1;
        } else if (upfInterface.isCore()) {
            actionId = FABRIC_INGRESS_SPGW_IFACE_CORE;
            gtpuValidity = 0;
        } else {
            throw new UpfProgrammableException("Unknown interface type");
        }

        PiCriterion match = PiCriterion.builder()
                .matchLpm(HDR_IPV4_DST_ADDR,
                        upfInterface.prefix().address().toInt(),
                        upfInterface.prefix().prefixLength())
                .matchExact(HDR_GTPU_IS_VALID, gtpuValidity)
                .build();
        PiAction action = PiAction.builder()
                .withId(actionId)
                .withParameter(new PiActionParam(SLICE_ID, DEFAULT_SLICE_ID))
                .build();
        return DefaultFlowRule.builder()
                .forDevice(deviceId).fromApp(appId).makePermanent()
                .forTable(FABRIC_INGRESS_SPGW_INTERFACES)
                .withSelector(DefaultTrafficSelector.builder().matchPi(match).build())
                .withTreatment(DefaultTrafficTreatment.builder().piTableAction(action).build())
                .withPriority(priority)
                .build();
    }

    /**
     * Builds FlowRules for the uplink recirculation table.
     *
     * @param deviceId the ID of the device the FlowRule should be installed on
     * @param appId    the ID of the application that will insert the FlowRule
     * @param src      the Ipv4 source prefix
     * @param dst      the Ipv4 destination prefix
     * @param allow    whether to allow or not (drop) recirculation
     * @param priority the FlowRule's priority
     * @return FlowRule for the uplink recirculation table
     */
    // FIXME: this method is specific to fabric-tna and might be removed once we create proper
    //   pipeconf behavior for fabric-v1model, unless we add the same uplink recirculation
    //   capability to that P4 program as well.
    public FlowRule buildFabricUplinkRecircEntry(DeviceId deviceId, ApplicationId appId,
                                                 Ip4Prefix src, Ip4Prefix dst,
                                                 boolean allow, int priority) {
        TrafficSelector.Builder selectorBuilder = DefaultTrafficSelector.builder();
        if (src != null) {
            selectorBuilder.matchIPSrc(src);
        }
        if (dst != null) {
            selectorBuilder.matchIPDst(dst);
        }
        PiAction action = PiAction.builder()
                .withId(allow ? FABRIC_INGRESS_SPGW_RECIRC_ALLOW
                        : FABRIC_INGRESS_SPGW_RECIRC_DENY)
                .build();
        return DefaultFlowRule.builder()
                .forDevice(deviceId).fromApp(appId).makePermanent()
                .forTable(FABRIC_INGRESS_SPGW_UPLINK_RECIRC_RULES)
                .withSelector(selectorBuilder.build())
                .withTreatment(DefaultTrafficTreatment.builder().piTableAction(action).build())
                .withPriority(priority)
                .build();
    }

    public FlowRule buildGtpuWithPscEncapRule(DeviceId deviceId, ApplicationId appId) {
        PiAction action = PiAction.builder()
                .withId(FABRIC_EGRESS_SPGW_GTPU_WITH_PSC)
                .build();
        // Default entry, no selector.
        return DefaultFlowRule.builder()
                .forDevice(deviceId).fromApp(appId).makePermanent()
                .forTable(FABRIC_EGRESS_SPGW_GTPU_ENCAP)
                .withTreatment(DefaultTrafficTreatment.builder().piTableAction(action).build())
                .withPriority(0)
                .build();
    }

    public FlowRule buildGtpuOnlyEncapRule(DeviceId deviceId, ApplicationId appId) {
        PiAction action = PiAction.builder()
                .withId(FABRIC_EGRESS_SPGW_GTPU_ONLY)
                .build();
        // Default entry, no selector.
        return DefaultFlowRule.builder()
                .forDevice(deviceId).fromApp(appId).makePermanent()
                .forTable(FABRIC_EGRESS_SPGW_GTPU_ENCAP)
                .withTreatment(DefaultTrafficTreatment.builder().piTableAction(action).build())
                .withPriority(0)
                .build();
    }
}
