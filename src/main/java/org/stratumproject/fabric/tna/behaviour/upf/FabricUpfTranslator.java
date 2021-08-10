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
import org.onosproject.net.behaviour.upf.ForwardingActionRule;
import org.onosproject.net.behaviour.upf.GtpTunnel;
import org.onosproject.net.behaviour.upf.PacketDetectionRule;
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
import static org.stratumproject.fabric.tna.behaviour.Constants.UPF_INTERFACE_ACCESS;
import static org.stratumproject.fabric.tna.behaviour.Constants.UPF_INTERFACE_CORE;
import static org.stratumproject.fabric.tna.behaviour.Constants.UPF_INTERFACE_DBUF;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.CTR_ID;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.DROP;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_EGRESS_SPGW_GTPU_ENCAP;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_EGRESS_SPGW_GTPU_ONLY;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_EGRESS_SPGW_GTPU_WITH_PSC;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_DOWNLINK_PDRS;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_FARS;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_INTERFACES;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_LOAD_DBUF_FAR;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_LOAD_IFACE;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_LOAD_NORMAL_FAR;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_LOAD_PDR;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_LOAD_TUNNEL_FAR;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_UPLINK_PDRS;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_UPLINK_RECIRC_ALLOW;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_UPLINK_RECIRC_DENY;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_UPLINK_RECIRC_RULES;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FAR_ID;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.HDR_FAR_ID;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.HDR_GTPU_IS_VALID;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.HDR_IPV4_DST_ADDR;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.HDR_TEID;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.HDR_TUNNEL_IPV4_DST;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.HDR_UE_ADDR;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.NEEDS_GTPU_DECAP;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.NOTIFY_CP;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.QFI;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.SLICE_ID;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.SRC_IFACE;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.TC;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.TEID;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.TUNNEL_DST_ADDR;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.TUNNEL_SRC_ADDR;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.TUNNEL_SRC_PORT;

/**
 * Provides logic to translate UPF entities into pipeline-specific ones and vice-versa.
 * Implementation should be stateless, with all state delegated to FabricUpfStore.
 */
public class FabricUpfTranslator {

    private final FabricUpfStore fabricUpfStore;

    // TODO: agree on a mapping with the PFCP agent
    //  Make sure to have a 1 to 1 mapping between QFI and TC.
    static final BiMap<Byte, Integer> QFI_TO_TC = ImmutableBiMap.of(
            //0, TC_BEST_EFFORT, --> this is DEFAULT_TC
            (byte) 1, TC_CONTROL,
            (byte) 2, TC_REAL_TIME,
            (byte) 3, TC_ELASTIC);

    public FabricUpfTranslator(FabricUpfStore fabricUpfStore) {
        this.fabricUpfStore = fabricUpfStore;
    }

    /**
     * Returns true if the given table entry is a Packet Detection Rule from the physical fabric pipeline, and
     * false otherwise.
     *
     * @param entry the entry that may or may not be a fabric.p4 PDR
     * @return true if the entry is a fabric.p4 PDR
     */
    public boolean isFabricPdr(FlowRule entry) {
        return entry.table().equals(FABRIC_INGRESS_SPGW_UPLINK_PDRS)
                || entry.table().equals(FABRIC_INGRESS_SPGW_DOWNLINK_PDRS);
    }

    /**
     * Returns true if the given table entry is a Forwarding Action Rule from the physical fabric pipeline, and
     * false otherwise.
     *
     * @param entry the entry that may or may not be a fabric.p4 FAR
     * @return true if the entry is a fabric.p4 FAR
     */
    public boolean isFabricFar(FlowRule entry) {
        return entry.table().equals(FABRIC_INGRESS_SPGW_FARS);
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
     * Translate a fabric.p4 PDR table entry to a PacketDetectionRule instance for easier handling.
     *
     * @param entry the fabric.p4 entry to translate
     * @return the corresponding PacketDetectionRule
     * @throws UpfProgrammableException if the entry cannot be translated
     */
    public PacketDetectionRule fabricEntryToPdr(FlowRule entry)
            throws UpfProgrammableException {
        var pdrBuilder = PacketDetectionRule.builder();
        Pair<PiCriterion, PiTableAction> matchActionPair = FabricUpfTranslatorUtil.fabricEntryToPiPair(entry);
        PiCriterion match = matchActionPair.getLeft();
        PiAction action = (PiAction) matchActionPair.getRight();

        // Grab keys and parameters that are present for all PDRs
        int globalFarId = FabricUpfTranslatorUtil.getParamInt(action, FAR_ID);
        UpfRuleIdentifier farId = fabricUpfStore.localFarIdOf(globalFarId);
        if (farId == null) {
            throw new UpfProgrammableException(format("Unable to find local far id of %s", globalFarId));
        }

        pdrBuilder.withCounterId(FabricUpfTranslatorUtil.getParamInt(action, CTR_ID))
                .withLocalFarId(farId.getSessionLocalId())
                .withSessionId(farId.getPfcpSessionId());

        if (FabricUpfTranslatorUtil.fieldIsPresent(match, HDR_TEID)) {
            // F-TEID is only present for GTP-matching PDRs
            ImmutableByteSequence teid = FabricUpfTranslatorUtil.getFieldValue(match, HDR_TEID);
            Ip4Address tunnelDst = FabricUpfTranslatorUtil.getFieldAddress(match, HDR_TUNNEL_IPV4_DST);
            pdrBuilder.withTeid(teid)
                    .withTunnelDst(tunnelDst);
        } else if (FabricUpfTranslatorUtil.fieldIsPresent(match, HDR_UE_ADDR)) {
            // And UE address is only present for non-GTP-matching PDRs
            pdrBuilder.withUeAddr(FabricUpfTranslatorUtil.getFieldAddress(match, HDR_UE_ADDR));
        } else {
            throw new UpfProgrammableException("Read malformed PDR from dataplane!:" + entry);
        }


        int tc = FabricUpfTranslatorUtil.getParamInt(action, TC);
        Byte qfi = QFI_TO_TC.inverse().getOrDefault(tc, null);
        if (qfi != null) {
            // FIXME: this breaks R/W symmetry as we always return a PDR wth a
            //  QFI even if we wrote one without. See comment in pdrToFabricEntry().
            pdrBuilder.withQfi(qfi);
        } else {
            throw new UpfProgrammableException(format(
                    "TC value '%d' unsupported, unable to map to QFI -- " +
                            "how did we manage to write this entry? BUG? [%s]",
                    tc, entry));
        }

        return pdrBuilder.build();
    }

    /**
     * Translate a fabric.p4 FAR table entry to a ForwardActionRule instance for easier handling.
     *
     * @param entry the fabric.p4 entry to translate
     * @return the corresponding ForwardingActionRule
     * @throws UpfProgrammableException if the entry cannot be translated
     */
    public ForwardingActionRule fabricEntryToFar(FlowRule entry)
            throws UpfProgrammableException {
        var farBuilder = ForwardingActionRule.builder();
        Pair<PiCriterion, PiTableAction> matchActionPair = FabricUpfTranslatorUtil.fabricEntryToPiPair(entry);
        PiCriterion match = matchActionPair.getLeft();
        PiAction action = (PiAction) matchActionPair.getRight();

        int globalFarId = FabricUpfTranslatorUtil.getFieldInt(match, HDR_FAR_ID);
        UpfRuleIdentifier farId = fabricUpfStore.localFarIdOf(globalFarId);
        if (farId == null) {
            throw new UpfProgrammableException(format("Unable to find local far id of %s", globalFarId));
        }

        boolean dropFlag = FabricUpfTranslatorUtil.getParamInt(action, DROP) > 0;
        boolean notifyFlag = FabricUpfTranslatorUtil.getParamInt(action, NOTIFY_CP) > 0;

        // Match keys
        farBuilder.withSessionId(farId.getPfcpSessionId())
                .setFarId(farId.getSessionLocalId());

        // Parameters common to all types of FARs
        farBuilder.setDropFlag(dropFlag)
                .setNotifyFlag(notifyFlag);

        PiActionId actionId = action.id();

        if (actionId.equals(FABRIC_INGRESS_SPGW_LOAD_TUNNEL_FAR)
                || actionId.equals(FABRIC_INGRESS_SPGW_LOAD_DBUF_FAR)) {
            // Grab parameters specific to encapsulating FARs if they're present
            Ip4Address tunnelSrc = FabricUpfTranslatorUtil.getParamAddress(action, TUNNEL_SRC_ADDR);
            Ip4Address tunnelDst = FabricUpfTranslatorUtil.getParamAddress(action, TUNNEL_DST_ADDR);
            ImmutableByteSequence teid = FabricUpfTranslatorUtil.getParamValue(action, TEID);
            short tunnelSrcPort = (short) FabricUpfTranslatorUtil.getParamInt(action, TUNNEL_SRC_PORT);

            farBuilder.setBufferFlag(actionId.equals(FABRIC_INGRESS_SPGW_LOAD_DBUF_FAR));

            farBuilder.setTunnel(
                    GtpTunnel.builder()
                            .setSrc(tunnelSrc)
                            .setDst(tunnelDst)
                            .setTeid(teid)
                            .setSrcPort(tunnelSrcPort)
                            .build());
        }
        return farBuilder.build();
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

        int interfaceType = FabricUpfTranslatorUtil.getParamInt(action, SRC_IFACE);
        if (interfaceType == UPF_INTERFACE_ACCESS) {
            ifaceBuilder.setAccess();
        } else if (interfaceType == UPF_INTERFACE_CORE) {
            ifaceBuilder.setCore();
        } else if (interfaceType == UPF_INTERFACE_DBUF) {
            ifaceBuilder.setDbufReceiver();
        }
        return ifaceBuilder.build();
    }

    /**
     * Translate a ForwardingActionRule to a FlowRule to be inserted into the fabric.p4 pipeline.
     * A side effect of calling this method is the FAR object's globalFarId is assigned if it was not already.
     *
     * @param far      The FAR to be translated
     * @param deviceId the ID of the device the FlowRule should be installed on
     * @param appId    the ID of the application that will insert the FlowRule
     * @param priority the FlowRule's priority
     * @return the FAR translated to a FlowRule
     * @throws UpfProgrammableException if the FAR to be translated is malformed
     */
    public FlowRule farToFabricEntry(ForwardingActionRule far, DeviceId deviceId, ApplicationId appId, int priority)
            throws UpfProgrammableException {
        PiAction action;
        if (!far.encaps()) {
            action = PiAction.builder()
                    .withId(FABRIC_INGRESS_SPGW_LOAD_NORMAL_FAR)
                    .withParameters(Arrays.asList(
                            new PiActionParam(DROP, far.drops() ? 1 : 0),
                            new PiActionParam(NOTIFY_CP, far.notifies() ? 1 : 0)
                    ))
                    .build();

        } else {
            if (far.tunnelSrc() == null || far.tunnelDst() == null
                    || far.teid() == null || far.tunnel().srcPort() == null) {
                throw new UpfProgrammableException(
                        "Not all action parameters present when translating " +
                                "intermediate encapsulating/buffering FAR to physical FAR!");
            }
            // TODO: copy tunnel destination port from logical switch write requests, instead of hardcoding 2152
            PiActionId actionId = far.buffers() ? FABRIC_INGRESS_SPGW_LOAD_DBUF_FAR :
                    FABRIC_INGRESS_SPGW_LOAD_TUNNEL_FAR;
            action = PiAction.builder()
                    .withId(actionId)
                    .withParameters(Arrays.asList(
                            new PiActionParam(DROP, far.drops() ? 1 : 0),
                            new PiActionParam(NOTIFY_CP, far.notifies() ? 1 : 0),
                            new PiActionParam(TEID, far.teid()),
                            new PiActionParam(TUNNEL_SRC_ADDR, far.tunnelSrc().toInt()),
                            new PiActionParam(TUNNEL_DST_ADDR, far.tunnelDst().toInt()),
                            new PiActionParam(TUNNEL_SRC_PORT, far.tunnel().srcPort())
                    ))
                    .build();
        }
        PiCriterion match = PiCriterion.builder()
                .matchExact(HDR_FAR_ID, fabricUpfStore.globalFarIdOf(far.sessionId(), far.farId()))
                .build();
        return DefaultFlowRule.builder()
                .forDevice(deviceId).fromApp(appId).makePermanent()
                .forTable(FABRIC_INGRESS_SPGW_FARS)
                .withSelector(DefaultTrafficSelector.builder().matchPi(match).build())
                .withTreatment(DefaultTrafficTreatment.builder().piTableAction(action).build())
                .withPriority(priority)
                .build();
    }

    /**
     * Translate a PacketDetectionRule to a FlowRule to be inserted into the fabric.p4 pipeline.
     * A side effect of calling this method is the PDR object's globalFarId is assigned if it was not already.
     *
     * @param pdr      The PDR to be translated
     * @param deviceId the ID of the device the FlowRule should be installed on
     * @param appId    the ID of the application that will insert the FlowRule
     * @param priority the FlowRule's priority
     * @return the FAR translated to a FlowRule
     * @throws UpfProgrammableException if the PDR to be translated is malformed
     */
    public FlowRule pdrToFabricEntry(PacketDetectionRule pdr, DeviceId deviceId, ApplicationId appId, int priority)
            throws UpfProgrammableException {
        // TODO: add QFI match and push to the pipeline
        if (pdr.matchQfi()) {
            throw new UpfProgrammableException("Match QFI not yet supported! Cannot translate " + pdr);
        } else if (pdr.pushQfi()) {
            throw new UpfProgrammableException("Push QFI not yet supported! Cannot translate " + pdr);
        }
        final PiCriterion match;
        final PiTableId tableId;

        final PiAction.Builder actionBuilder = PiAction.builder()
                .withParameters(Arrays.asList(
                        new PiActionParam(CTR_ID, pdr.counterId()),
                        new PiActionParam(FAR_ID, fabricUpfStore.globalFarIdOf(pdr.sessionId(), pdr.farId())),
                        new PiActionParam(NEEDS_GTPU_DECAP, pdr.matchesEncapped() ? 1 : 0)))
                .withId(FABRIC_INGRESS_SPGW_LOAD_PDR);

        final int tc;
        if (pdr.hasQfi()) {
            if(!QFI_TO_TC.containsKey(pdr.qfi())) {
                throw new UpfProgrammableException(format(
                        "QFI value '%d' not supported, unable to map to TC", pdr.qfi()));
            }
            tc = QFI_TO_TC.get(pdr.qfi());
        } else {
            // FIXME: this breaks R/W symmetry, as we cannot distinguish between
            //   QFI=0 and QFI unset, indeed both cases map to the same
            //   Best-Effort TC. We should use different actions for PDRs
            //   without QFI to maintain R/W symmetry with PFCP agent.
            tc = TC_BEST_EFFORT;
        }
        actionBuilder.withParameter(new PiActionParam(TC, tc));

        if (pdr.matchesEncapped()) {
            match = PiCriterion.builder()
                    .matchExact(HDR_TEID, pdr.teid().asArray())
                    .matchExact(HDR_TUNNEL_IPV4_DST, pdr.tunnelDest().toInt())
                    .build();
            tableId = FABRIC_INGRESS_SPGW_UPLINK_PDRS;
        } else if (pdr.matchesUnencapped()) {
            match = PiCriterion.builder()
                    .matchExact(HDR_UE_ADDR, pdr.ueAddress().toInt())
                    .build();
            tableId = FABRIC_INGRESS_SPGW_DOWNLINK_PDRS;
        } else {
            throw new UpfProgrammableException("Flexible PDRs not yet supported! Cannot translate " + pdr);
        }

        return DefaultFlowRule.builder()
                .forDevice(deviceId).fromApp(appId).makePermanent()
                .forTable(tableId)
                .withSelector(DefaultTrafficSelector.builder().matchPi(match).build())
                .withTreatment(DefaultTrafficTreatment.builder().piTableAction(actionBuilder.build()).build())
                .withPriority(priority)
                .build();
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
        if (upfInterface.isDbufReceiver()) {
            interfaceTypeInt = UPF_INTERFACE_DBUF;
            gtpuValidity = 1;
        } else if (upfInterface.isAccess()) {
            interfaceTypeInt = UPF_INTERFACE_ACCESS;
            gtpuValidity = 1;
        } else {
            interfaceTypeInt = UPF_INTERFACE_CORE;
            gtpuValidity = 0;
        }

        PiCriterion match = PiCriterion.builder()
                .matchLpm(HDR_IPV4_DST_ADDR,
                        upfInterface.prefix().address().toInt(),
                        upfInterface.prefix().prefixLength())
                .matchExact(HDR_GTPU_IS_VALID, gtpuValidity)
                .build();
        PiAction action = PiAction.builder()
                .withId(FABRIC_INGRESS_SPGW_LOAD_IFACE)
                .withParameter(new PiActionParam(SRC_IFACE, interfaceTypeInt))
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
                .withId(allow ? FABRIC_INGRESS_SPGW_UPLINK_RECIRC_ALLOW
                        : FABRIC_INGRESS_SPGW_UPLINK_RECIRC_DENY)
                .build();
        return DefaultFlowRule.builder()
                .forDevice(deviceId).fromApp(appId).makePermanent()
                .forTable(FABRIC_INGRESS_SPGW_UPLINK_RECIRC_RULES)
                .withSelector(selectorBuilder.build())
                .withTreatment(DefaultTrafficTreatment.builder().piTableAction(action).build())
                .withPriority(priority)
                .build();
    }

    public FlowRule buildGtpuWithPscEncapRule(DeviceId deviceId, ApplicationId appId, int qfi) {
        PiAction action = PiAction.builder()
                .withId(FABRIC_EGRESS_SPGW_GTPU_WITH_PSC)
                .withParameter(new PiActionParam(QFI, qfi))
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
