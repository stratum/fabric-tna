// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.behaviour.upf;

import org.onlab.packet.Ip4Address;
import org.onlab.packet.Ip4Prefix;
import org.onlab.util.ImmutableByteSequence;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.DefaultApplicationId;
import org.onosproject.net.DeviceId;
import org.onosproject.net.behaviour.upf.ForwardingActionRule;
import org.onosproject.net.behaviour.upf.PacketDetectionRule;
import org.onosproject.net.behaviour.upf.UpfInterface;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.criteria.PiCriterion;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiActionParam;

import java.util.Arrays;

import static org.stratumproject.fabric.tna.behaviour.Constants.INTERFACE_ACCESS;
import static org.stratumproject.fabric.tna.behaviour.Constants.INTERFACE_CORE;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.CTR_ID;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.DROP;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_DOWNLINK_PDRS;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_FARS;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_INTERFACES;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_LOAD_IFACE;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_LOAD_NORMAL_FAR;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_LOAD_PDR;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_LOAD_PDR_QOS;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_LOAD_TUNNEL_FAR;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_UPLINK_PDRS;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FAR_ID;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.HDR_FAR_ID;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.HDR_GTPU_IS_VALID;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.HDR_IPV4_DST_ADDR;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.HDR_TEID;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.HDR_TUNNEL_IPV4_DST;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.HDR_UE_ADDR;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.NEEDS_GTPU_DECAP;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.NOTIFY_CP;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.QID;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.SRC_IFACE;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.TEID;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.TUNNEL_DST_ADDR;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.TUNNEL_SRC_ADDR;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.TUNNEL_SRC_PORT;

public final class TestUpfConstants {
    public static final DeviceId DEVICE_ID = DeviceId.deviceId("CoolSwitch91");
    public static final ApplicationId APP_ID = new DefaultApplicationId(5000, "up4");
    public static final int DEFAULT_PRIORITY = 10;
    // SESSION_ID_BITWIDTH / 8 = 12
    public static final ImmutableByteSequence SESSION_ID = ImmutableByteSequence.ofOnes(12);
    public static final int UPLINK_COUNTER_CELL_ID = 1;
    public static final int DOWNLINK_COUNTER_CELL_ID = 2;
    public static final int PDR_ID = 0;  // TODO: PDR ID currently not stored on writes, so all reads are 0
    public static final int UPLINK_FAR_ID = 1;
    public static final int UPLINK_PHYSICAL_FAR_ID = 4;
    public static final int DOWNLINK_FAR_ID = 2;
    public static final int DOWNLINK_PHYSICAL_FAR_ID = 5;

    public static final int UPLINK_PRIORITY = 9;
    public static final int DOWNLINK_PRIORITY = 1;
    public static final int UPLINK_QID = 1;
    public static final int DOWNLINK_QID = 5;
    public static final int DEFAULT_SCHEDULING_PRIORITY = 0;

    public static final ImmutableByteSequence TEID_VALUE = ImmutableByteSequence.copyFrom(0xff);
    public static final Ip4Address UE_ADDR = Ip4Address.valueOf("17.0.0.1");
    public static final Ip4Address S1U_ADDR = Ip4Address.valueOf("192.168.0.1");
    public static final Ip4Address ENB_ADDR = Ip4Address.valueOf("192.168.0.2");
    public static final Ip4Prefix UE_POOL = Ip4Prefix.valueOf("17.0.0.0/16");
    // TODO: tunnel source port currently not stored on writes, so all reads are 0
    public static final short TUNNEL_SPORT = 2160;
    public static final int PHYSICAL_COUNTER_SIZE = 512;
    public static final int PHYSICAL_MAX_PDRS = 512;
    public static final int PHYSICAL_MAX_FARS = 512;

    public static final long COUNTER_BYTES = 12;
    public static final long COUNTER_PKTS = 15;

    public static final PacketDetectionRule UPLINK_PDR = PacketDetectionRule.builder()
            .withTunnelDst(S1U_ADDR)
            .withTeid(TEID_VALUE)
            .withLocalFarId(UPLINK_FAR_ID)
            .withSessionId(SESSION_ID)
            .withCounterId(UPLINK_COUNTER_CELL_ID)
            .withSchedulingPriority(DEFAULT_SCHEDULING_PRIORITY)
            .build();

    public static final PacketDetectionRule DOWNLINK_PDR = PacketDetectionRule.builder()
            .withUeAddr(UE_ADDR)
            .withLocalFarId(DOWNLINK_FAR_ID)
            .withSessionId(SESSION_ID)
            .withCounterId(DOWNLINK_COUNTER_CELL_ID)
            .withSchedulingPriority(DEFAULT_SCHEDULING_PRIORITY)
            .build();

    public static final PacketDetectionRule UPLINK_PRIORITY_PDR = PacketDetectionRule.builder()
            .withTunnelDst(S1U_ADDR)
            .withTeid(TEID_VALUE)
            .withLocalFarId(UPLINK_FAR_ID)
            .withSessionId(SESSION_ID)
            .withCounterId(UPLINK_COUNTER_CELL_ID)
            .withSchedulingPriority(UPLINK_PRIORITY)
            .build();

    public static final PacketDetectionRule DOWNLINK_PRIORITY_PDR = PacketDetectionRule.builder()
            .withUeAddr(UE_ADDR)
            .withLocalFarId(DOWNLINK_FAR_ID)
            .withSessionId(SESSION_ID)
            .withCounterId(DOWNLINK_COUNTER_CELL_ID)
            .withSchedulingPriority(DOWNLINK_PRIORITY)
            .build();

    public static final ForwardingActionRule UPLINK_FAR = ForwardingActionRule.builder()
            .setFarId(UPLINK_FAR_ID)
            .withSessionId(SESSION_ID).build();

    public static final ForwardingActionRule DOWNLINK_FAR = ForwardingActionRule.builder()
            .setFarId(DOWNLINK_FAR_ID)
            .withSessionId(SESSION_ID)
            .setTunnel(S1U_ADDR, ENB_ADDR, TEID_VALUE, TUNNEL_SPORT)
            .build();

    public static final UpfInterface UPLINK_INTERFACE = UpfInterface.createS1uFrom(S1U_ADDR);

    public static final UpfInterface DOWNLINK_INTERFACE = UpfInterface.createUePoolFrom(UE_POOL);

    public static final FlowRule FABRIC_UPLINK_PRIORITY_PDR = DefaultFlowRule.builder()
            .forDevice(DEVICE_ID).fromApp(APP_ID).makePermanent()
            .forTable(FABRIC_INGRESS_SPGW_UPLINK_PDRS)
            .withSelector(DefaultTrafficSelector.builder().matchPi(PiCriterion.builder()
                                                                           .matchExact(HDR_TEID, TEID_VALUE.asArray())
                                                                           .matchExact(HDR_TUNNEL_IPV4_DST, S1U_ADDR.toInt())
                                                                           .build()).build())
            .withTreatment(DefaultTrafficTreatment.builder().piTableAction(PiAction.builder()
                                                                                   .withId(FABRIC_INGRESS_SPGW_LOAD_PDR_QOS)
                                                                                   .withParameters(Arrays.asList(
                                                                                           new PiActionParam(CTR_ID, UPLINK_COUNTER_CELL_ID),
                                                                                           new PiActionParam(FAR_ID, UPLINK_PHYSICAL_FAR_ID),
                                                                                           new PiActionParam(NEEDS_GTPU_DECAP, 1),
                                                                                           new PiActionParam(QID, UPLINK_QID)
                                                                                   ))
                                                                                   .build()).build())
            .withPriority(DEFAULT_PRIORITY)
            .build();

    public static final FlowRule FABRIC_DOWNLINK_PRIORITY_PDR = DefaultFlowRule.builder()
            .forDevice(DEVICE_ID).fromApp(APP_ID).makePermanent()
            .forTable(FABRIC_INGRESS_SPGW_DOWNLINK_PDRS)
            .withSelector(DefaultTrafficSelector.builder().matchPi(PiCriterion.builder()
                                                                           .matchExact(HDR_UE_ADDR, UE_ADDR.toInt())
                                                                           .build()).build())
            .withTreatment(DefaultTrafficTreatment.builder().piTableAction(PiAction.builder()
                                                                                   .withId(FABRIC_INGRESS_SPGW_LOAD_PDR_QOS)
                                                                                   .withParameters(Arrays.asList(
                                                                                           new PiActionParam(CTR_ID, DOWNLINK_COUNTER_CELL_ID),
                                                                                           new PiActionParam(FAR_ID, DOWNLINK_PHYSICAL_FAR_ID),
                                                                                           new PiActionParam(NEEDS_GTPU_DECAP, 0),
                                                                                           new PiActionParam(QID, DOWNLINK_QID)
                                                                                   ))
                                                                                   .build()).build())
            .withPriority(DEFAULT_PRIORITY)
            .build();

    public static final FlowRule FABRIC_UPLINK_PDR = DefaultFlowRule.builder()
            .forDevice(DEVICE_ID).fromApp(APP_ID).makePermanent()
            .forTable(FABRIC_INGRESS_SPGW_UPLINK_PDRS)
            .withSelector(DefaultTrafficSelector.builder().matchPi(PiCriterion.builder()
                                                                           .matchExact(HDR_TEID, TEID_VALUE.asArray())
                                                                           .matchExact(HDR_TUNNEL_IPV4_DST, S1U_ADDR.toInt())
                                                                           .build()).build())
            .withTreatment(DefaultTrafficTreatment.builder().piTableAction(PiAction.builder()
                                                                                   .withId(FABRIC_INGRESS_SPGW_LOAD_PDR)
                                                                                   .withParameters(Arrays.asList(
                                                                                           new PiActionParam(CTR_ID, UPLINK_COUNTER_CELL_ID),
                                                                                           new PiActionParam(FAR_ID, UPLINK_PHYSICAL_FAR_ID),
                                                                                           new PiActionParam(NEEDS_GTPU_DECAP, 1)
                                                                                   ))
                                                                                   .build()).build())
            .withPriority(DEFAULT_PRIORITY)
            .build();

    public static final FlowRule FABRIC_DOWNLINK_PDR = DefaultFlowRule.builder()
            .forDevice(DEVICE_ID).fromApp(APP_ID).makePermanent()
            .forTable(FABRIC_INGRESS_SPGW_DOWNLINK_PDRS)
            .withSelector(DefaultTrafficSelector.builder().matchPi(PiCriterion.builder()
                                                                           .matchExact(HDR_UE_ADDR, UE_ADDR.toInt())
                                                                           .build()).build())
            .withTreatment(DefaultTrafficTreatment.builder().piTableAction(PiAction.builder()
                                                                                   .withId(FABRIC_INGRESS_SPGW_LOAD_PDR)
                                                                                   .withParameters(Arrays.asList(
                                                                                           new PiActionParam(CTR_ID, DOWNLINK_COUNTER_CELL_ID),
                                                                                           new PiActionParam(FAR_ID, DOWNLINK_PHYSICAL_FAR_ID),
                                                                                           new PiActionParam(NEEDS_GTPU_DECAP, 0)
                                                                                   ))
                                                                                   .build()).build())
            .withPriority(DEFAULT_PRIORITY)
            .build();

    public static final FlowRule FABRIC_UPLINK_FAR = DefaultFlowRule.builder()
            .forDevice(DEVICE_ID).fromApp(APP_ID).makePermanent()
            .forTable(FABRIC_INGRESS_SPGW_FARS)
            .withSelector(DefaultTrafficSelector.builder().matchPi(PiCriterion.builder()
                                                                           .matchExact(HDR_FAR_ID, UPLINK_PHYSICAL_FAR_ID)
                                                                           .build()).build())
            .withTreatment(DefaultTrafficTreatment.builder().piTableAction(PiAction.builder()
                                                                                   .withId(FABRIC_INGRESS_SPGW_LOAD_NORMAL_FAR)
                                                                                   .withParameters(Arrays.asList(
                                                                                           new PiActionParam(DROP, 0),
                                                                                           new PiActionParam(NOTIFY_CP, 0)
                                                                                   ))
                                                                                   .build()).build())
            .withPriority(DEFAULT_PRIORITY)
            .build();

    public static final FlowRule FABRIC_DOWNLINK_FAR = DefaultFlowRule.builder()
            .forDevice(DEVICE_ID).fromApp(APP_ID).makePermanent()
            .forTable(FABRIC_INGRESS_SPGW_FARS)
            .withSelector(DefaultTrafficSelector.builder().matchPi(PiCriterion.builder()
                                                                           .matchExact(HDR_FAR_ID, DOWNLINK_PHYSICAL_FAR_ID)
                                                                           .build()).build())
            .withTreatment(DefaultTrafficTreatment.builder().piTableAction(PiAction.builder()
                                                                                   .withId(FABRIC_INGRESS_SPGW_LOAD_TUNNEL_FAR)
                                                                                   .withParameters(Arrays.asList(
                                                                                           new PiActionParam(DROP, 0),
                                                                                           new PiActionParam(NOTIFY_CP, 0),
                                                                                           new PiActionParam(TEID, TEID_VALUE),
                                                                                           new PiActionParam(TUNNEL_SRC_ADDR, S1U_ADDR.toInt()),
                                                                                           new PiActionParam(TUNNEL_DST_ADDR, ENB_ADDR.toInt()),
                                                                                           new PiActionParam(TUNNEL_SRC_PORT, TUNNEL_SPORT)
                                                                                   ))
                                                                                   .build()).build())
            .withPriority(DEFAULT_PRIORITY)
            .build();

    public static final FlowRule FABRIC_UPLINK_INTERFACE = DefaultFlowRule.builder()
            .forDevice(DEVICE_ID).fromApp(APP_ID).makePermanent()
            .forTable(FABRIC_INGRESS_SPGW_INTERFACES)
            .withSelector(DefaultTrafficSelector.builder().matchPi(PiCriterion.builder()
                                                                           .matchLpm(HDR_IPV4_DST_ADDR,
                                                                                     S1U_ADDR.toInt(),
                                                                                     32)
                                                                           .matchExact(HDR_GTPU_IS_VALID, 1)
                                                                           .build()).build())
            .withTreatment(DefaultTrafficTreatment.builder().piTableAction(PiAction.builder()
                                                                                   .withId(FABRIC_INGRESS_SPGW_LOAD_IFACE)
                                                                                   .withParameter(new PiActionParam(SRC_IFACE, INTERFACE_ACCESS))
                                                                                   .build()).build())
            .withPriority(DEFAULT_PRIORITY)
            .build();

    public static final FlowRule FABRIC_DOWNLINK_INTERFACE = DefaultFlowRule.builder()
            .forDevice(DEVICE_ID).fromApp(APP_ID).makePermanent()
            .forTable(FABRIC_INGRESS_SPGW_INTERFACES)
            .withSelector(DefaultTrafficSelector.builder().matchPi(PiCriterion.builder()
                                                                           .matchLpm(HDR_IPV4_DST_ADDR,
                                                                                     UE_POOL.address().toInt(),
                                                                                     UE_POOL.prefixLength())
                                                                           .matchExact(HDR_GTPU_IS_VALID, 0)
                                                                           .build()).build())
            .withTreatment(DefaultTrafficTreatment.builder().piTableAction(PiAction.builder()
                                                                                   .withId(FABRIC_INGRESS_SPGW_LOAD_IFACE)
                                                                                   .withParameter(new PiActionParam(SRC_IFACE, INTERFACE_CORE))
                                                                                   .build()).build())
            .withPriority(DEFAULT_PRIORITY)
            .build();

    /**
     * Hidden constructor for utility class.
     */
    private TestUpfConstants() {
    }
}
