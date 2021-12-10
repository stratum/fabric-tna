// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.behaviour.upf;

import org.onlab.packet.Ip4Address;
import org.onlab.packet.Ip4Prefix;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.DefaultApplicationId;
import org.onosproject.net.DeviceId;
import org.onosproject.net.behaviour.upf.GtpTunnelPeer;
import org.onosproject.net.behaviour.upf.UeSession;
import org.onosproject.net.behaviour.upf.UpfInterface;
import org.onosproject.net.behaviour.upf.UpfTermination;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.criteria.PiCriterion;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiActionParam;

import java.util.Arrays;

import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.CTR_ID;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_EGRESS_SPGW_EG_TUNNEL_PEERS;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_EGRESS_SPGW_LOAD_TUNNEL_PARAMS;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_APP_FWD;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_DOWNLINK_FWD_ENCAP;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_DOWNLINK_SESSIONS;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_DOWNLINK_TERMINATIONS;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_IFACE_ACCESS;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_IFACE_CORE;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_IG_TUNNEL_PEERS;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_INTERFACES;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_SET_DOWNLINK_SESSION;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_SET_DOWNLINK_SESSION_DBUF;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_SET_ROUTING_IPV4_DST;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_SPGW_SET_UPLINK_SESSION;
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

public final class TestUpfConstants {
    public static final DeviceId DEVICE_ID = DeviceId.deviceId("CoolSwitch91");
    public static final ApplicationId APP_ID = new DefaultApplicationId(5000, "up4");
    public static final int DEFAULT_PRIORITY = 10;
    private static final byte DEFAULT_SLICE_ID = 0;
    private static final byte DEFAULT_TC = 0;
    public static final int UPLINK_COUNTER_CELL_ID = 1;
    public static final int DOWNLINK_COUNTER_CELL_ID = 2;

    public static final byte UPLINK_QFI = 0x1;
    public static final byte UPLINK_TC = 0x1;
    public static final byte DOWNLINK_QFI = 0x3;
    public static final byte DOWNLINK_TC = 0x3;

    public static final byte ENB_GTP_TUNNEL_PEER = 0x2;
    public static final byte DBUF_TUNNEL_PEER = 0x1;
    public static final int TEID_VALUE = 0xff;
    public static final int TEID_VALUE_QOS = 0xfe;
    public static final Ip4Address UE_ADDR = Ip4Address.valueOf("17.0.0.1");
    public static final Ip4Address UE_ADDR_QOS = Ip4Address.valueOf("17.0.0.2");
    public static final Ip4Address S1U_ADDR = Ip4Address.valueOf("192.168.0.1");
    public static final Ip4Address ENB_ADDR = Ip4Address.valueOf("192.168.0.2");
    public static final Ip4Prefix UE_POOL = Ip4Prefix.valueOf("17.0.0.0/16");
    // TODO: tunnel source port currently not stored on writes, so all reads are 0
    public static final short TUNNEL_SPORT = 2160;
    public static final int PHYSICAL_COUNTER_SIZE = 512;
    public static final int PHYSICAL_MAX_UE_SESSIONS = 512;
    public static final int PHYSICAL_MAX_UPF_TERMINATIONS = 512;
    public static final int PHYSICAL_MAX_TUNNELS = 256;

    public static final long COUNTER_BYTES = 12;
    public static final long COUNTER_PKTS = 15;

    public static final GtpTunnelPeer GTP_TUNNEL_PEER = GtpTunnelPeer.builder()
            .withTunnelPeerId(ENB_GTP_TUNNEL_PEER)
            .withSrcAddr(S1U_ADDR)
            .withDstAddr(ENB_ADDR)
            .withSrcPort(TUNNEL_SPORT)
            .build();

    public static final UeSession UPLINK_UE_SESSION = UeSession.builder()
            .withTeid(TEID_VALUE)
            .withIpv4Address(S1U_ADDR)
            .build();

    public static final UeSession DOWNLINK_UE_SESSION = UeSession.builder()
            .withIpv4Address(UE_ADDR)
            .withGtpTunnelPeerId(ENB_GTP_TUNNEL_PEER)
            .build();

    public static final UeSession DOWNLINK_UE_SESSION_DBUF = UeSession.builder()
            .withIpv4Address(UE_ADDR)
            .withGtpTunnelPeerId(DBUF_TUNNEL_PEER)
            .withBuffering(true)
            .build();

    public static final UpfTermination UPLINK_UPF_TERMINATION = UpfTermination.builder()
            .withUeSessionId(UE_ADDR)
            .withCounterId(UPLINK_COUNTER_CELL_ID)
            .withTrafficClass(UPLINK_TC)
            .build();

    public static final UpfTermination DOWNLINK_UPF_TERMINATION = UpfTermination.builder()
            .withUeSessionId(UE_ADDR)
            .withCounterId(DOWNLINK_COUNTER_CELL_ID)
            .withTrafficClass(DOWNLINK_TC)
            .withTeid(TEID_VALUE)
            .withQfi((byte) 0)
            .build();

    public static final UpfTermination DOWNLINK_UPF_TERMINATION_QOS = UpfTermination.builder()
            .withUeSessionId(UE_ADDR_QOS)
            .withCounterId(DOWNLINK_COUNTER_CELL_ID)
            .withTrafficClass(DOWNLINK_TC)
            .withTeid(TEID_VALUE_QOS)
            .withQfi(DOWNLINK_QFI)
            .build();

    public static final UpfTermination UPLINK_UPF_TERMINATION_QOS = UpfTermination.builder()
            .withUeSessionId(UE_ADDR_QOS)
            .withCounterId(UPLINK_COUNTER_CELL_ID)
            .withTrafficClass(UPLINK_TC)
            .build();

    // TODO: what about GtpTunnelPeer?

    public static final UpfInterface UPLINK_INTERFACE = UpfInterface.createS1uFrom(S1U_ADDR);

    public static final UpfInterface DOWNLINK_INTERFACE = UpfInterface.createUePoolFrom(UE_POOL);

    public static final FlowRule FABRIC_INGRESS_GTP_TUNNEL_PEER = DefaultFlowRule.builder()
            .forDevice(DEVICE_ID).fromApp(APP_ID).makePermanent()
            .forTable(FABRIC_INGRESS_SPGW_IG_TUNNEL_PEERS)
            .withSelector(DefaultTrafficSelector.builder()
                    .matchPi(PiCriterion.builder()
                            .matchExact(HDR_TUN_PEER_ID, ENB_GTP_TUNNEL_PEER)
                            .build()).build())
            .withTreatment(DefaultTrafficTreatment.builder()
                    .piTableAction(
                            PiAction.builder()
                                    .withId(FABRIC_INGRESS_SPGW_SET_ROUTING_IPV4_DST)
                                    .withParameter(new PiActionParam(TUN_DST_ADDR, ENB_ADDR.toInt()))
                                    .build()).build())
            .withPriority(DEFAULT_PRIORITY)
            .build();

    public static final FlowRule FABRIC_EGRESS_GTP_TUNNEL_PEER = DefaultFlowRule.builder()
            .forDevice(DEVICE_ID).fromApp(APP_ID).makePermanent()
            .forTable(FABRIC_EGRESS_SPGW_EG_TUNNEL_PEERS)
            .withSelector(DefaultTrafficSelector.builder()
                    .matchPi(PiCriterion.builder()
                            .matchExact(HDR_TUN_PEER_ID, ENB_GTP_TUNNEL_PEER)
                            .build()).build())
            .withTreatment(DefaultTrafficTreatment.builder()
                    .piTableAction(
                            PiAction.builder()
                                    .withId(FABRIC_EGRESS_SPGW_LOAD_TUNNEL_PARAMS)
                                    .withParameters(Arrays.asList(
                                            new PiActionParam(TUNNEL_SRC_ADDR, S1U_ADDR.toInt()),
                                            new PiActionParam(TUNNEL_DST_ADDR, ENB_ADDR.toInt()),
                                            new PiActionParam(TUNNEL_SRC_PORT, TUNNEL_SPORT)
                                    ))
                                    .build()).build())
            .withPriority(DEFAULT_PRIORITY)
            .build();

    public static final FlowRule FABRIC_UPLINK_UE_SESSION = DefaultFlowRule.builder()
            .forDevice(DEVICE_ID).fromApp(APP_ID).makePermanent()
            .forTable(FABRIC_INGRESS_SPGW_UPLINK_SESSIONS)
            .withSelector(DefaultTrafficSelector.builder()
                                    .matchPi(PiCriterion.builder()
                                            .matchExact(HDR_TEID, TEID_VALUE)
                                            .matchExact(HDR_TUNNEL_IPV4_DST, S1U_ADDR.toInt())
                                            .build()).build())
            .withTreatment(DefaultTrafficTreatment.builder()
                    .piTableAction(PiAction.builder()
                            .withId(FABRIC_INGRESS_SPGW_SET_UPLINK_SESSION)
                            .build()).build())
            .withPriority(DEFAULT_PRIORITY)
            .build();

    public static final FlowRule FABRIC_DOWNLINK_UE_SESSION = DefaultFlowRule.builder()
            .forDevice(DEVICE_ID).fromApp(APP_ID).makePermanent()
            .forTable(FABRIC_INGRESS_SPGW_DOWNLINK_SESSIONS)
            .withSelector(DefaultTrafficSelector.builder()
                    .matchPi(PiCriterion.builder()
                            .matchExact(HDR_UE_ADDR, UE_ADDR.toInt())
                            .build()).build())
            .withTreatment(DefaultTrafficTreatment.builder()
                    .piTableAction(
                            PiAction.builder()
                                    .withId(FABRIC_INGRESS_SPGW_SET_DOWNLINK_SESSION)
                                    .withParameter(new PiActionParam(TUN_PEER_ID, ENB_GTP_TUNNEL_PEER))
                                    .build()).build())
            .withPriority(DEFAULT_PRIORITY)
            .build();

    public static final FlowRule FABRIC_DOWNLINK_UE_SESSION_DBUF = DefaultFlowRule.builder()
            .forDevice(DEVICE_ID).fromApp(APP_ID).makePermanent()
            .forTable(FABRIC_INGRESS_SPGW_DOWNLINK_SESSIONS)
            .withSelector(DefaultTrafficSelector.builder()
                                  .matchPi(PiCriterion.builder()
                                                   .matchExact(HDR_UE_ADDR, UE_ADDR.toInt())
                                                   .build()).build())
            .withTreatment(DefaultTrafficTreatment.builder()
                                   .piTableAction(
                                           PiAction.builder()
                                                   .withId(FABRIC_INGRESS_SPGW_SET_DOWNLINK_SESSION_DBUF)
                                                   .withParameter(new PiActionParam(TUN_PEER_ID, DBUF_TUNNEL_PEER))
                                                   .build()).build())
            .withPriority(DEFAULT_PRIORITY)
            .build();

    public static final FlowRule FABRIC_UPLINK_UPF_TERMINATION = DefaultFlowRule.builder()
            .forDevice(DEVICE_ID).fromApp(APP_ID).makePermanent()
            .forTable(FABRIC_INGRESS_SPGW_UPLINK_TERMINATIONS)
            .withSelector(DefaultTrafficSelector.builder()
                    .matchPi(PiCriterion.builder()
                            // we don't match on slice_id, because we assume distinct UE pools per slice
                            .matchExact(HDR_UE_SESSION_ID, UE_ADDR.toInt())
                            .build()).build())
            .withTreatment(DefaultTrafficTreatment.builder()
                    .piTableAction(PiAction.builder()
                            .withId(FABRIC_INGRESS_SPGW_APP_FWD)
                            .withParameters(Arrays.asList(
                                    new PiActionParam(CTR_ID, UPLINK_COUNTER_CELL_ID),
                                    new PiActionParam(TC, UPLINK_TC)
                            ))
                            .build()).build())
            .withPriority(DEFAULT_PRIORITY)
            .build();

    public static final FlowRule FABRIC_UPLINK_UPF_TERMINATION_QOS = DefaultFlowRule.builder()
            .forDevice(DEVICE_ID).fromApp(APP_ID).makePermanent()
            .forTable(FABRIC_INGRESS_SPGW_UPLINK_TERMINATIONS)
            .withSelector(DefaultTrafficSelector.builder()
                    .matchPi(PiCriterion.builder()
                            // we don't match on slice_id, because we assume distinct UE pools per slice
                            .matchExact(HDR_UE_SESSION_ID, UE_ADDR_QOS.toInt())
                            .build()).build())
            .withTreatment(DefaultTrafficTreatment.builder()
                    .piTableAction(PiAction.builder()
                            .withId(FABRIC_INGRESS_SPGW_APP_FWD)
                            .withParameters(Arrays.asList(
                                    new PiActionParam(CTR_ID, UPLINK_COUNTER_CELL_ID),
                                    new PiActionParam(TC, UPLINK_TC)
                            ))
                            .build()).build())
            .withPriority(DEFAULT_PRIORITY)
            .build();

    public static final FlowRule FABRIC_DOWNLINK_UPF_TERMINATION = DefaultFlowRule.builder()
            .forDevice(DEVICE_ID).fromApp(APP_ID).makePermanent()
            .forTable(FABRIC_INGRESS_SPGW_DOWNLINK_TERMINATIONS)
            .withSelector(DefaultTrafficSelector.builder()
                    .matchPi(PiCriterion.builder()
                            // we don't match on slice_id, because we assume distinct UE pools per slice
                            .matchExact(HDR_UE_SESSION_ID, UE_ADDR.toInt())
                            .build()).build())
            .withTreatment(DefaultTrafficTreatment.builder()
                    .piTableAction(PiAction.builder()
                            .withId(FABRIC_INGRESS_SPGW_DOWNLINK_FWD_ENCAP)
                            .withParameters(Arrays.asList(
                                    new PiActionParam(CTR_ID, DOWNLINK_COUNTER_CELL_ID),
                                    new PiActionParam(TC, DOWNLINK_TC),
                                    new PiActionParam(TEID, TEID_VALUE),
                                    new PiActionParam(QFI, (byte) 0)  // 4G case
                            ))
                            .build()).build())
            .withPriority(DEFAULT_PRIORITY)
            .build();

    public static final FlowRule FABRIC_DOWNLINK_UPF_TERMINATION_QOS = DefaultFlowRule.builder()
            .forDevice(DEVICE_ID).fromApp(APP_ID).makePermanent()
            .forTable(FABRIC_INGRESS_SPGW_DOWNLINK_TERMINATIONS)
            .withSelector(DefaultTrafficSelector.builder()
                    .matchPi(PiCriterion.builder()
                            // we don't match on slice_id, becuase we assume distint UE pools per slice
                            .matchExact(HDR_UE_SESSION_ID, UE_ADDR_QOS.toInt())
                            .build()).build())
            .withTreatment(DefaultTrafficTreatment.builder()
                    .piTableAction(PiAction.builder()
                            .withId(FABRIC_INGRESS_SPGW_DOWNLINK_FWD_ENCAP)
                            .withParameters(Arrays.asList(
                                    new PiActionParam(CTR_ID, DOWNLINK_COUNTER_CELL_ID),
                                    new PiActionParam(TC, DOWNLINK_TC),
                                    new PiActionParam(TEID, TEID_VALUE_QOS),
                                    new PiActionParam(QFI, DOWNLINK_QFI)  // 5G case
                            ))
                            .build()).build())
            .withPriority(DEFAULT_PRIORITY)
            .build();

    public static final FlowRule FABRIC_UPLINK_INTERFACE = DefaultFlowRule.builder()
            .forDevice(DEVICE_ID).fromApp(APP_ID).makePermanent()
            .forTable(FABRIC_INGRESS_SPGW_INTERFACES)
            .withSelector(DefaultTrafficSelector.builder()
                                  .matchPi(PiCriterion.builder()
                                                   .matchLpm(HDR_IPV4_DST_ADDR,
                                                             S1U_ADDR.toInt(),
                                                             32)
                                                   .matchExact(HDR_GTPU_IS_VALID, 1)
                                                   .build()).build())
            .withTreatment(
                    DefaultTrafficTreatment.builder()
                            .piTableAction(
                                    PiAction.builder()
                                            .withId(FABRIC_INGRESS_SPGW_IFACE_ACCESS)
                                            .withParameter(new PiActionParam(SLICE_ID, DEFAULT_SLICE_ID))
                                            .build()).build())
            .withPriority(DEFAULT_PRIORITY)
            .build();

    public static final FlowRule FABRIC_DOWNLINK_INTERFACE = DefaultFlowRule.builder()
            .forDevice(DEVICE_ID).fromApp(APP_ID).makePermanent()
            .forTable(FABRIC_INGRESS_SPGW_INTERFACES)
            .withSelector(DefaultTrafficSelector.builder()
                                  .matchPi(PiCriterion.builder()
                                                   .matchLpm(HDR_IPV4_DST_ADDR,
                                                             UE_POOL.address().toInt(),
                                                             UE_POOL.prefixLength())
                                                   .matchExact(HDR_GTPU_IS_VALID, 0)
                                                   .build()).build())
            .withTreatment(
                    DefaultTrafficTreatment.builder()
                            .piTableAction(PiAction.builder()
                                                   .withId(FABRIC_INGRESS_SPGW_IFACE_CORE)
                                                   .withParameter(new PiActionParam(SLICE_ID, DEFAULT_SLICE_ID))
                                                   .build()).build())
            .withPriority(DEFAULT_PRIORITY)
            .build();

    /**
     * Hidden constructor for utility class.
     */
    private TestUpfConstants() {
    }
}
