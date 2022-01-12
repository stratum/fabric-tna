// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.behaviour.upf;

import org.apache.commons.lang3.tuple.Pair;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.Ip4Prefix;
import org.onosproject.core.ApplicationId;
import org.onosproject.net.DeviceId;
import org.onosproject.net.behaviour.upf.GtpTunnelPeer;
import org.onosproject.net.behaviour.upf.SessionDownlink;
import org.onosproject.net.behaviour.upf.SessionUplink;
import org.onosproject.net.behaviour.upf.UpfInterface;
import org.onosproject.net.behaviour.upf.UpfProgrammableException;
import org.onosproject.net.behaviour.upf.UpfTerminationDownlink;
import org.onosproject.net.behaviour.upf.UpfTerminationUplink;
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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.CTR_ID;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_EGRESS_SPGW_EG_TUNNEL_PEERS;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_EGRESS_SPGW_GTPU_ENCAP;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_EGRESS_SPGW_GTPU_ONLY;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_EGRESS_SPGW_GTPU_WITH_PSC;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_EGRESS_SPGW_LOAD_TUNNEL_PARAMS;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_APP_FWD;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_DOWNLINK_DROP;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_DOWNLINK_FWD_ENCAP;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_DOWNLINK_SESSIONS;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_DOWNLINK_TERMINATIONS;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_IFACE_ACCESS;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_IFACE_CORE;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_IFACE_DBUF;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_IG_TUNNEL_PEERS;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_INTERFACES;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_RECIRC_ALLOW;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_RECIRC_DENY;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_SET_DOWNLINK_SESSION;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_SET_DOWNLINK_SESSION_BUF;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_SET_DOWNLINK_SESSION_BUF_DROP;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_SET_DOWNLINK_SESSION_DROP;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_SET_ROUTING_IPV4_DST;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_SET_UPLINK_SESSION;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_SET_UPLINK_SESSION_DROP;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_UPLINK_DROP;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_UPLINK_RECIRC_RULES;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_UPLINK_SESSIONS;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_UPLINK_TERMINATIONS;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.HDR_GTPU_IS_VALID;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.HDR_IPV4_DST_ADDR;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.HDR_TEID;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.HDR_TUNNEL_IPV4_DST;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.HDR_TUN_PEER_ID;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.HDR_UE_ADDR;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.HDR_UE_SESSION_ID;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.QFI;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.SLICE_ID;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.TC;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.TEID;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.TUNNEL_DST_ADDR;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.TUNNEL_SRC_ADDR;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.TUNNEL_SRC_PORT;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.TUN_DST_ADDR;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.TUN_PEER_ID;

/**
 * Provides logic to translate UPF entities into pipeline-specific ones and vice-versa.
 * Implementation should be stateless, with all state delegated to FabricUpfStore.
 */
public class FabricUpfTranslator {
    /**
     * Returns true if the given table entry is a GTP tunnel peer rule from the
     * physical fabric pipeline, and false otherwise.
     *
     * @param entry the flow rule entry
     * @return true if the entry is a fabric.p4 GTP tunnel peer
     */
    public boolean isFabricGtpTunnelPeer(FlowRule entry) {
        // we return egress tunnel_peers table, because only this table
        // contains all necessary information to create GtpTunnelPeer instance.
        return entry.table().equals(FABRIC_EGRESS_SPGW_EG_TUNNEL_PEERS);
    }

    /**
     * Returns true if the given table entry is a uplink UE Session rule from the physical fabric pipeline, and
     * false otherwise.
     *
     * @param entry the entry that may or may not be a fabric.p4 UE Session rule
     * @return true if the entry is a fabric.p4 UE Session rule
     */
    public boolean isFabricUeSessionUplink(FlowRule entry) {
        return entry.table().equals(FABRIC_INGRESS_SPGW_UPLINK_SESSIONS);
    }


    /**
     * Returns true if the given table entry is a downlink UE Session rule from the physical fabric pipeline, and
     * false otherwise.
     *
     * @param entry the entry that may or may not be a fabric.p4 UE Session rule
     * @return true if the entry is a fabric.p4 UE Session rule
     */
    public boolean isFabricUeSessionDownlink(FlowRule entry) {
        return entry.table().equals(FABRIC_INGRESS_SPGW_DOWNLINK_SESSIONS);
    }

    /**
     * Returns true if the given table entry is a UPF Termination rule from the physical fabric pipeline, and
     * false otherwise.
     *
     * @param entry the entry that may or may not be a fabric.p4 UPF Termination rule
     * @return true if the entry is a fabric.p4 UPF Termination rule
     */
    public boolean isFabricUpfTerminationUplink(FlowRule entry) {
        return entry.table().equals(FABRIC_INGRESS_SPGW_UPLINK_TERMINATIONS);
    }

    /**
     * Returns true if the given table entry is a UPF Termination rule from the physical fabric pipeline, and
     * false otherwise.
     *
     * @param entry the entry that may or may not be a fabric.p4 UPF Termination rule
     * @return true if the entry is a fabric.p4 UPF Termination rule
     */
    public boolean isFabricUpfTerminationDownlink(FlowRule entry) {
        return entry.table().equals(FABRIC_INGRESS_SPGW_DOWNLINK_TERMINATIONS);
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

    private void assertTableId(FlowRule entry, PiTableId tableId) throws UpfProgrammableException {
        if (!entry.table().equals(tableId)) {
            throw new UpfProgrammableException(
                    "The FlowRule for " + tableId + " expected, provided: " + entry);
        }
    }

    /**
     * Translate a fabric.p4 GTP tunnel peer table entry to a GtpTunnelPeer instance for easier handling.
     *
     * @param entry the fabric.p4 entry to translate, the method expects FlowRule from eg_tunnel_peers table.
     * @return the corresponding GtpTunnelPeer
     * @throws UpfProgrammableException if the entry cannot be translated
     */
    public GtpTunnelPeer fabricEntryToGtpTunnelPeer(FlowRule entry)
            throws UpfProgrammableException {
        assertTableId(entry, FABRIC_EGRESS_SPGW_EG_TUNNEL_PEERS);
        GtpTunnelPeer.Builder builder = GtpTunnelPeer.builder();

        Pair<PiCriterion, PiTableAction> matchActionPair = FabricUpfTranslatorUtil.fabricEntryToPiPair(entry);
        PiCriterion match = matchActionPair.getLeft();
        PiAction action = (PiAction) matchActionPair.getRight();
        builder.withTunnelPeerId(FabricUpfTranslatorUtil.getFieldByte(match, HDR_TUN_PEER_ID));

        if (!action.id().equals(FABRIC_EGRESS_SPGW_LOAD_TUNNEL_PARAMS)) {
            throw new UpfProgrammableException(
                    "Invalid action provided, cannot build GtpTunnelPeer instance: " + action.id());
        }

        builder.withSrcAddr(FabricUpfTranslatorUtil.getParamAddress(action, TUNNEL_SRC_ADDR))
                .withDstAddr(FabricUpfTranslatorUtil.getParamAddress(action, TUNNEL_DST_ADDR))
                .withSrcPort((short) FabricUpfTranslatorUtil.getParamInt(action, TUNNEL_SRC_PORT));

        return builder.build();
    }

    /**
     * Translate a fabric.p4 session table entry to a UeSession instance for easier handling.
     *
     * @param entry the fabric.p4 entry to translate
     * @return the corresponding UeSession
     * @throws UpfProgrammableException if the entry cannot be translated
     */
    public SessionUplink fabricEntryToUeSessionUplink(FlowRule entry)
            throws UpfProgrammableException {
        assertTableId(entry, FABRIC_INGRESS_SPGW_UPLINK_SESSIONS);
        SessionUplink.Builder builder = SessionUplink.builder();

        Pair<PiCriterion, PiTableAction> matchActionPair = FabricUpfTranslatorUtil.fabricEntryToPiPair(entry);
        PiCriterion match = matchActionPair.getLeft();
        PiAction action = (PiAction) matchActionPair.getRight();
        if (!(FabricUpfTranslatorUtil.fieldIsPresent(match, HDR_TEID) ||
                FabricUpfTranslatorUtil.fieldIsPresent(match, HDR_TUNNEL_IPV4_DST))) {
            throw new UpfProgrammableException("Malformed uplink session from dataplane!: " + entry);
        }
        builder.withTunDstAddr(FabricUpfTranslatorUtil.getFieldAddress(match, HDR_TUNNEL_IPV4_DST))
                .withTeid(FabricUpfTranslatorUtil.getFieldInt(match, HDR_TEID));

        PiActionId actionId = action.id();
        if (actionId.equals(FABRIC_INGRESS_SPGW_SET_UPLINK_SESSION_DROP)) {
            builder.needsDropping(true);
        }
        return builder.build();
    }

    /**
     * Translate a fabric.p4 session table entry to a UeSession instance for easier handling.
     *
     * @param entry the fabric.p4 entry to translate
     * @return the corresponding UeSession
     * @throws UpfProgrammableException if the entry cannot be translated
     */
    public SessionDownlink fabricEntryToUeSessionDownlink(FlowRule entry)
            throws UpfProgrammableException {
        assertTableId(entry, FABRIC_INGRESS_SPGW_DOWNLINK_SESSIONS);
        SessionDownlink.Builder builder = SessionDownlink.builder();
        Pair<PiCriterion, PiTableAction> matchActionPair = FabricUpfTranslatorUtil.fabricEntryToPiPair(entry);
        PiCriterion match = matchActionPair.getLeft();
        PiAction action = (PiAction) matchActionPair.getRight();
        if (!FabricUpfTranslatorUtil.fieldIsPresent(match, HDR_UE_ADDR)) {
            throw new UpfProgrammableException("Malformed downlink session from dataplane!: " + entry);
        }
        builder.withUeAddress(FabricUpfTranslatorUtil.getFieldAddress(match, HDR_UE_ADDR));
        PiActionId actionId = action.id();
        if (actionId.equals(FABRIC_INGRESS_SPGW_SET_DOWNLINK_SESSION_DROP)) {
            builder.needsDropping(true);
        } else if (actionId.equals(FABRIC_INGRESS_SPGW_SET_DOWNLINK_SESSION_BUF_DROP)) {
            builder.needsDropping(true);
            builder.needsBuffering(true);
        } else {
            builder.withGtpTunnelPeerId(FabricUpfTranslatorUtil.getParamByte(action, TUN_PEER_ID));
            if (actionId.equals(FABRIC_INGRESS_SPGW_SET_DOWNLINK_SESSION_BUF)) {
                builder.needsBuffering(true);
            }
        }
        return builder.build();
    }

    /**
     * Translate a fabric.p4 termination table entry to a uplink UpfTermination instance for easier handling.
     *
     * @param entry the fabric.p4 entry to translate
     * @return the corresponding UpfTerminationUplink
     * @throws UpfProgrammableException if the entry cannot be translated
     */
    public UpfTerminationUplink fabricEntryToUpfTerminationUplink(FlowRule entry)
            throws UpfProgrammableException {
        assertTableId(entry, FABRIC_INGRESS_SPGW_UPLINK_TERMINATIONS);
        UpfTerminationUplink.Builder builder = UpfTerminationUplink.builder();
        Pair<PiCriterion, PiTableAction> matchActionPair = FabricUpfTranslatorUtil.fabricEntryToPiPair(entry);
        PiCriterion match = matchActionPair.getLeft();
        PiAction action = (PiAction) matchActionPair.getRight();

        if (!FabricUpfTranslatorUtil.fieldIsPresent(match, HDR_UE_SESSION_ID)) {
            throw new UpfProgrammableException("Malformed uplink termination from dataplane!: " + entry);
        }
        // Match keys
        Ip4Address ueSessionId = FabricUpfTranslatorUtil.getFieldAddress(match, HDR_UE_SESSION_ID);
        builder.withUeSessionId(ueSessionId);

        PiActionId actionId = action.id();
        builder.withCounterId(FabricUpfTranslatorUtil.getParamInt(action, CTR_ID));
        if (actionId.equals(FABRIC_INGRESS_SPGW_UPLINK_DROP)) {
            builder.needsDropping(true);
        } else {
            builder.withTrafficClass(FabricUpfTranslatorUtil.getParamByte(action, TC));
        }
        return builder.build();
    }

    /**
     * Translate a fabric.p4 termination table entry to a downlink UpfTermination instance for easier handling.
     *
     * @param entry the fabric.p4 entry to translate
     * @return the corresponding UpfTerminationDownlink
     * @throws UpfProgrammableException if the entry cannot be translated
     */
    public UpfTerminationDownlink fabricEntryToUpfTerminationDownlink(FlowRule entry)
            throws UpfProgrammableException {
        assertTableId(entry, FABRIC_INGRESS_SPGW_DOWNLINK_TERMINATIONS);
        UpfTerminationDownlink.Builder builder = UpfTerminationDownlink.builder();
        Pair<PiCriterion, PiTableAction> matchActionPair = FabricUpfTranslatorUtil.fabricEntryToPiPair(entry);
        PiCriterion match = matchActionPair.getLeft();
        PiAction action = (PiAction) matchActionPair.getRight();

        if (!FabricUpfTranslatorUtil.fieldIsPresent(match, HDR_UE_SESSION_ID)) {
            throw new UpfProgrammableException("Malformed downlink termination from dataplane!: " + entry);
        }
        // Match keys
        Ip4Address ueSessionId = FabricUpfTranslatorUtil.getFieldAddress(match, HDR_UE_SESSION_ID);
        builder.withUeSessionId(ueSessionId);

        PiActionId actionId = action.id();
        builder.withCounterId(FabricUpfTranslatorUtil.getParamInt(action, CTR_ID));
        if (actionId.equals(FABRIC_INGRESS_SPGW_DOWNLINK_DROP)) {
            builder.needsDropping(true);
        } else {
            // Parameters common to all types of UPF Termination rules
            builder.withTrafficClass(FabricUpfTranslatorUtil.getParamByte(action, TC))
                    .withTeid(FabricUpfTranslatorUtil.getParamInt(action, TEID))
                    .withQfi(FabricUpfTranslatorUtil.getParamByte(action, QFI));
        }
        return builder.build();
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
        assertTableId(entry, FABRIC_INGRESS_SPGW_INTERFACES);
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
     * Translate a GtpTunnelPeer to two FlowRules to be inserted into the fabric.p4 pipeline.
     *
     * @param gtpTunnelPeer the GTP tunnel peer to be translated
     * @param deviceId      the ID of the device the FlowRule should be installed on
     * @param appId         the ID of the application that will insert the FlowRule
     * @param priority      the FlowRules' priority
     * @return a pair of FlowRules translated from GTP tunnel peer
     * @throws UpfProgrammableException if the interface cannot be translated
     */
    public Pair<FlowRule, FlowRule> gtpTunnelPeerToFabricEntry(GtpTunnelPeer gtpTunnelPeer, DeviceId deviceId,
                                                               ApplicationId appId, int priority)
            throws UpfProgrammableException {
        FlowRule ingressEntry;
        FlowRule egressEntry;

        if (gtpTunnelPeer.src() == null || gtpTunnelPeer.dst() == null) {
            throw new UpfProgrammableException(
                    "Not all action parameters present when translating " +
                            "intermediate GTP tunnel peer to physical representation!");
        }

        PiCriterion match = PiCriterion.builder()
                .matchExact(HDR_TUN_PEER_ID, gtpTunnelPeer.tunPeerId())
                .build();

        FlowRule.Builder base = DefaultFlowRule.builder()
                .forDevice(deviceId).fromApp(appId).makePermanent()
                .withPriority(priority)
                .withSelector(DefaultTrafficSelector.builder().matchPi(match).build());

        PiAction ingressAction = PiAction.builder()
                .withId(FABRIC_INGRESS_SPGW_SET_ROUTING_IPV4_DST)
                .withParameter(new PiActionParam(TUN_DST_ADDR, gtpTunnelPeer.dst().toInt()))
                .build();
        ingressEntry = base.forTable(FABRIC_INGRESS_SPGW_IG_TUNNEL_PEERS)
                .withTreatment(DefaultTrafficTreatment.builder().piTableAction(ingressAction).build())
                .build();

        PiAction egressAction = PiAction.builder()
                .withId(FABRIC_EGRESS_SPGW_LOAD_TUNNEL_PARAMS)
                .withParameters(Arrays.asList(
                        new PiActionParam(TUNNEL_SRC_ADDR, gtpTunnelPeer.src().toInt()),
                        new PiActionParam(TUNNEL_DST_ADDR, gtpTunnelPeer.dst().toInt()),
                        new PiActionParam(TUNNEL_SRC_PORT, gtpTunnelPeer.srcPort())
                ))
                .build();
        egressEntry = base.forTable(FABRIC_EGRESS_SPGW_EG_TUNNEL_PEERS)
                .withTreatment(DefaultTrafficTreatment.builder().piTableAction(egressAction).build())
                .build();

        return Pair.of(ingressEntry, egressEntry);
    }

    /**
     * Translate a uplink session to a FlowRule to be inserted into the fabric.p4 pipeline.
     *
     * @param ueSession The uplink UE Session to be translated
     * @param deviceId  the ID of the device the FlowRule should be installed on
     * @param appId     the ID of the application that will insert the FlowRule
     * @param priority  the FlowRule's priority
     * @return the uplink ue session translated to a FlowRule
     * @throws UpfProgrammableException if the UE session cannot be translated
     */
    public FlowRule sessionUplinkToFabricEntry(SessionUplink ueSession, DeviceId deviceId,
                                               ApplicationId appId, int priority)
            throws UpfProgrammableException {
        final PiCriterion match;
        final PiAction.Builder actionBuilder = PiAction.builder();

        match = PiCriterion.builder()
                .matchExact(HDR_TEID, ueSession.teid())
                .matchExact(HDR_TUNNEL_IPV4_DST, ueSession.tunDstAddr().toOctets())
                .build();
        if (ueSession.needsDropping()) {
            actionBuilder.withId(FABRIC_INGRESS_SPGW_SET_UPLINK_SESSION_DROP);
        } else {
            actionBuilder.withId(FABRIC_INGRESS_SPGW_SET_UPLINK_SESSION);
        }
        return DefaultFlowRule.builder()
                .forDevice(deviceId)
                .fromApp(appId)
                .makePermanent()
                .forTable(FABRIC_INGRESS_SPGW_UPLINK_SESSIONS)
                .withSelector(DefaultTrafficSelector.builder().matchPi(match).build())
                .withTreatment(DefaultTrafficTreatment.builder().piTableAction(actionBuilder.build()).build())
                .withPriority(priority)
                .build();
    }

    /**
     * Translate a downlink session to a FlowRule to be inserted into the fabric.p4 pipeline.
     *
     * @param ueSession The downlink UE Session to be translated
     * @param deviceId  the ID of the device the FlowRule should be installed on
     * @param appId     the ID of the application that will insert the FlowRule
     * @param priority  the FlowRule's priority
     * @return the downlink ue session translated to a FlowRule
     * @throws UpfProgrammableException if the UE session cannot be translated
     */
    public FlowRule sessionDownlinkToFabricEntry(SessionDownlink ueSession, DeviceId deviceId,
                                                 ApplicationId appId, int priority)
            throws UpfProgrammableException {
        final PiCriterion match;
        final PiAction.Builder actionBuilder = PiAction.builder();

        match = PiCriterion.builder()
                .matchExact(HDR_UE_ADDR, ueSession.ueAddress().toOctets())
                .build();
        if (ueSession.needsDropping() && ueSession.needsBuffering()) {
            actionBuilder.withId(FABRIC_INGRESS_SPGW_SET_DOWNLINK_SESSION_BUF_DROP);
        } else if (ueSession.needsDropping()) {
            actionBuilder.withId(FABRIC_INGRESS_SPGW_SET_DOWNLINK_SESSION_DROP);
        } else {
            actionBuilder.withParameter(new PiActionParam(TUN_PEER_ID, ueSession.tunPeerId()));
            if (ueSession.needsBuffering()) {
                actionBuilder.withId(FABRIC_INGRESS_SPGW_SET_DOWNLINK_SESSION_BUF);
            } else {
                actionBuilder.withId(FABRIC_INGRESS_SPGW_SET_DOWNLINK_SESSION);
            }
        }
        return DefaultFlowRule.builder()
                .forDevice(deviceId)
                .fromApp(appId)
                .makePermanent()
                .forTable(FABRIC_INGRESS_SPGW_DOWNLINK_SESSIONS)
                .withSelector(DefaultTrafficSelector.builder().matchPi(match).build())
                .withTreatment(DefaultTrafficTreatment.builder().piTableAction(actionBuilder.build()).build())
                .withPriority(priority)
                .build();
    }

    /**
     * Translate a Uplink UpfTermination to a FlowRule to be inserted into the fabric.p4 pipeline.
     *
     * @param upfTermination The uplink UPF Termination to be translated
     * @param deviceId       the ID of the device the FlowRule should be installed on
     * @param appId          the ID of the application that will insert the FlowRule
     * @param priority       the FlowRule's priority
     * @return the uplink UPF Termination translated to a FlowRule
     * @throws UpfProgrammableException if the UPF Termination cannot be translated
     */
    public FlowRule upfTerminationUplinkToFabricEntry(
            UpfTerminationUplink upfTermination, DeviceId deviceId,
            ApplicationId appId, int priority)
            throws UpfProgrammableException {
        final PiCriterion match = PiCriterion.builder()
                .matchExact(HDR_UE_SESSION_ID, upfTermination.ueSessionId().toInt())
                .build();
        final PiAction.Builder actionBuilder = PiAction.builder();

        List<PiActionParam> paramList = new ArrayList<>(Arrays.asList(
                new PiActionParam(CTR_ID, upfTermination.counterId())
        ));

        if (upfTermination.needsDropping()) {
            actionBuilder.withId(FABRIC_INGRESS_SPGW_DOWNLINK_DROP);
        } else {
            actionBuilder.withId(FABRIC_INGRESS_SPGW_APP_FWD);
            paramList.add(new PiActionParam(TC, upfTermination.trafficClass()));
        }
        actionBuilder.withParameters(paramList);

        return DefaultFlowRule.builder()
                .forDevice(deviceId)
                .fromApp(appId)
                .makePermanent()
                .forTable(FABRIC_INGRESS_SPGW_UPLINK_TERMINATIONS)
                .withSelector(DefaultTrafficSelector.builder().matchPi(match).build())
                .withTreatment(DefaultTrafficTreatment.builder().piTableAction(actionBuilder.build()).build())
                .withPriority(priority)
                .build();
    }

    /**
     * Translate a downlink UpfTermination to a FlowRule to be inserted into the fabric.p4 pipeline.
     *
     * @param upfTermination The downlink UPF Termination to be translated
     * @param deviceId       the ID of the device the FlowRule should be installed on
     * @param appId          the ID of the application that will insert the FlowRule
     * @param priority       the FlowRule's priority
     * @return the downlink UPF Termination translated to a FlowRule
     * @throws UpfProgrammableException if the UPF Termination cannot be translated
     */
    public FlowRule upfTerminationDownlinkToFabricEntry(
            UpfTerminationDownlink upfTermination, DeviceId deviceId,
            ApplicationId appId, int priority)
            throws UpfProgrammableException {
        final PiCriterion match = PiCriterion.builder()
                .matchExact(HDR_UE_SESSION_ID, upfTermination.ueSessionId().toInt())
                .build();
        final PiAction.Builder actionBuilder = PiAction.builder();

        List<PiActionParam> paramList = new ArrayList<>(Arrays.asList(
                new PiActionParam(CTR_ID, upfTermination.counterId())
        ));

        if (upfTermination.needsDropping()) {
            actionBuilder.withId(FABRIC_INGRESS_SPGW_DOWNLINK_DROP);
        } else {
            actionBuilder.withId(FABRIC_INGRESS_SPGW_DOWNLINK_FWD_ENCAP);
            paramList.add(new PiActionParam(TC, upfTermination.trafficClass()));
            paramList.add(new PiActionParam(TEID, upfTermination.teid()));
            paramList.add(new PiActionParam(QFI, upfTermination.qfi()));
        }
        actionBuilder.withParameters(paramList);

        return DefaultFlowRule.builder()
                .forDevice(deviceId)
                .fromApp(appId)
                .makePermanent()
                .forTable(FABRIC_INGRESS_SPGW_DOWNLINK_TERMINATIONS)
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
                // FIXME: slice id should come from UP4
                .withParameter(new PiActionParam(SLICE_ID, 99))
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
