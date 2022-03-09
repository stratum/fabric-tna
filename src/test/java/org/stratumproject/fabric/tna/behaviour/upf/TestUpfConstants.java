// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0
package org.stratumproject.fabric.tna.behaviour.upf;

import com.google.common.collect.Lists;
import com.google.common.collect.Range;
import org.apache.commons.lang3.tuple.Pair;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.Ip4Prefix;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.DefaultApplicationId;
import org.onosproject.net.DeviceId;
import org.onosproject.net.behaviour.upf.UpfApplication;
import org.onosproject.net.behaviour.upf.UpfGtpTunnelPeer;
import org.onosproject.net.behaviour.upf.UpfInterface;
import org.onosproject.net.behaviour.upf.UpfMeter;
import org.onosproject.net.behaviour.upf.UpfSessionDownlink;
import org.onosproject.net.behaviour.upf.UpfSessionUplink;
import org.onosproject.net.behaviour.upf.UpfTerminationDownlink;
import org.onosproject.net.behaviour.upf.UpfTerminationUplink;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.criteria.PiCriterion;
import org.onosproject.net.meter.Band;
import org.onosproject.net.meter.DefaultBand;
import org.onosproject.net.meter.DefaultMeter;
import org.onosproject.net.meter.DefaultMeterRequest;
import org.onosproject.net.meter.Meter;
import org.onosproject.net.meter.MeterRequest;
import org.onosproject.net.meter.MeterScope;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiActionParam;
import org.onosproject.net.pi.runtime.PiMeterCellId;
import org.stratumproject.fabric.tna.behaviour.P4InfoConstants;

import java.util.Arrays;

import static org.onosproject.net.meter.Meter.Unit.BYTES_PER_SEC;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.APP_METER_IDX;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.CTR_ID;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_EGRESS_UPF_EG_TUNNEL_PEERS;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_EGRESS_UPF_LOAD_TUNNEL_PARAMS;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_QOS_SLICE_TC_METER;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_UPF_APPLICATIONS;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_UPF_APP_FWD;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_UPF_APP_METER;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_UPF_DOWNLINK_DROP;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_UPF_DOWNLINK_FWD_ENCAP;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_UPF_DOWNLINK_SESSIONS;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_UPF_DOWNLINK_TERMINATIONS;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_UPF_IFACE_ACCESS;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_UPF_IFACE_CORE;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_UPF_IG_TUNNEL_PEERS;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_UPF_INTERFACES;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_UPF_SESSION_METER;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_UPF_SET_APP_ID;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_UPF_SET_DOWNLINK_SESSION;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_UPF_SET_DOWNLINK_SESSION_BUF;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_UPF_SET_ROUTING_IPV4_DST;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_UPF_SET_UPLINK_SESSION;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_UPF_UPLINK_DROP;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_UPF_UPLINK_SESSIONS;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_UPF_UPLINK_TERMINATIONS;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.HDR_APP_ID;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.HDR_APP_IPV4_ADDR;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.HDR_APP_IP_PROTO;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.HDR_APP_L4_PORT;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.HDR_GTPU_IS_VALID;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.HDR_IPV4_DST_ADDR;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.HDR_SLICE_ID;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.HDR_TEID;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.HDR_TUNNEL_IPV4_DST;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.HDR_TUN_PEER_ID;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.HDR_UE_ADDR;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.HDR_UE_SESSION_ID;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.QFI;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.SESSION_METER_IDX;
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
    public static final int SLICE_MOBILE = 10;
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
    public static final Ip4Address N3_ADDR = Ip4Address.valueOf("192.168.0.1");
    public static final Ip4Address ENB_ADDR = Ip4Address.valueOf("192.168.0.2");
    public static final Ip4Prefix UE_POOL = Ip4Prefix.valueOf("17.0.0.0/16");
    // TODO: tunnel source port currently not stored on writes, so all reads are 0
    public static final short TUNNEL_SPORT = 2160;
    public static final int PHYSICAL_COUNTER_SIZE = 512;
    public static final int PHYSICAL_SESSION_METER_SIZE = 512;
    public static final int PHYSICAL_APP_METER_SIZE = 512;
    public static final int PHYSICAL_MAX_UE_SESSIONS = 512;
    public static final int PHYSICAL_MAX_UPF_TERMINATIONS = 512;
    public static final int PHYSICAL_MAX_TUNNELS = 256;
    public static final int PHYSICAL_MAX_APPLICATIONS = 5;
    public static final int PHYSICAL_MAX_SLICE_METERS = 1 << 6;


    public static final long COUNTER_BYTES = 12;
    public static final long COUNTER_PKTS = 15;

    public static final byte APP_FILTERING_ID = 10;
    public static final byte DEFAULT_APP_ID = 0;
    public static final int APP_FILTERING_PRIORITY = 10;
    public static final Ip4Prefix APP_IP_PREFIX = Ip4Prefix.valueOf("10.0.0.0/24");
    public static final Pair<Short, Short> APP_L4_RANGE = Pair.of((short) 100, (short) 1000);
    public static final byte APP_IP_PROTO = 6;

    public static final int METER_CELL_ID = 10;
    public static final short DEFAULT_APP_METER_IDX = 0;
    public static final int PIR = 10000;
    public static final int PBURST = 1000;
    public static final int CIR = 5000;
    public static final int CBURST = 500;

    public static final UpfGtpTunnelPeer GTP_TUNNEL_PEER = UpfGtpTunnelPeer.builder()
            .withTunnelPeerId(ENB_GTP_TUNNEL_PEER)
            .withSrcAddr(N3_ADDR)
            .withDstAddr(ENB_ADDR)
            .withSrcPort(TUNNEL_SPORT)
            .build();

    public static final UpfSessionUplink UPLINK_UE_SESSION = UpfSessionUplink.builder()
            .withTeid(TEID_VALUE)
            .withTunDstAddr(N3_ADDR)
            .withSessionMeterIdx(METER_CELL_ID)
            .build();

    public static final UpfSessionDownlink DOWNLINK_UE_SESSION = UpfSessionDownlink.builder()
            .withUeAddress(UE_ADDR)
            .withGtpTunnelPeerId(ENB_GTP_TUNNEL_PEER)
            .withSessionMeterIdx(METER_CELL_ID)
            .build();

    public static final UpfSessionDownlink DOWNLINK_UE_SESSION_DBUF = UpfSessionDownlink.builder()
            .withUeAddress(UE_ADDR)
            .withGtpTunnelPeerId(DBUF_TUNNEL_PEER)
            .needsBuffering(true)
            .withSessionMeterIdx(METER_CELL_ID)
            .build();

    public static final UpfTerminationUplink UPLINK_UPF_TERMINATION = UpfTerminationUplink.builder()
            .withUeSessionId(UE_ADDR)
            .withApplicationId(APP_FILTERING_ID)
            .withCounterId(UPLINK_COUNTER_CELL_ID)
            .withTrafficClass(UPLINK_TC)
            .withAppMeterIdx(METER_CELL_ID)
            .build();

    public static final UpfTerminationUplink UPLINK_UPF_TERMINATION_DROP = UpfTerminationUplink.builder()
            .withUeSessionId(UE_ADDR)
            .withCounterId(UPLINK_COUNTER_CELL_ID)
            .needsDropping(true)
            .build();

    public static final UpfTerminationDownlink DOWNLINK_UPF_TERMINATION = UpfTerminationDownlink.builder()
            .withUeSessionId(UE_ADDR)
            .withApplicationId(APP_FILTERING_ID)
            .withCounterId(DOWNLINK_COUNTER_CELL_ID)
            .withTrafficClass(DOWNLINK_TC)
            .withTeid(TEID_VALUE_QOS)
            .withQfi(DOWNLINK_QFI)
            .withAppMeterIdx(METER_CELL_ID)
            .build();

    public static final UpfApplication APPLICATION_FILTERING = UpfApplication.builder()
            .withAppId(APP_FILTERING_ID)
            .withIp4Prefix(APP_IP_PREFIX)
            .withL4PortRange(Range.closed(APP_L4_RANGE.getLeft(), APP_L4_RANGE.getRight()))
            .withIpProto(APP_IP_PROTO)
            .withPriority(APP_FILTERING_PRIORITY)
            .withSliceId(SLICE_MOBILE)
            .build();

    public static final UpfApplication APPLICATION_FILTERING_INVALID_SLICE_ID = UpfApplication.builder()
            .withAppId(APP_FILTERING_ID)
            .withIp4Prefix(APP_IP_PREFIX)
            .withPriority(APP_FILTERING_PRIORITY)
            .withSliceId(0)
            .build();

    public static final UpfTerminationDownlink DOWNLINK_UPF_TERMINATION_DROP = UpfTerminationDownlink.builder()
            .withUeSessionId(UE_ADDR)
            .withCounterId(DOWNLINK_COUNTER_CELL_ID)
            .needsDropping(true)
            .build();

    public static final UpfInterface UPLINK_INTERFACE = UpfInterface.createN3From(N3_ADDR, SLICE_MOBILE);

    public static final UpfInterface DOWNLINK_INTERFACE = UpfInterface.createUePoolFrom(UE_POOL, SLICE_MOBILE);

    public static final UpfMeter APP_METER = UpfMeter.builder()
            .setApplication()
            .setCellId(METER_CELL_ID)
            .setPeakBand(PIR, PBURST)
            .setCommittedBand(CIR, CBURST)
            .build();

    public static final UpfMeter APP_METER_RESET = UpfMeter.resetApplication(METER_CELL_ID);

    public static final UpfMeter SESSION_METER = UpfMeter.builder()
            .setSession()
            .setCellId(METER_CELL_ID)
            .setPeakBand(PIR, PBURST)
            .build();

    public static final UpfMeter SESSION_METER_RESET = UpfMeter.resetSession(METER_CELL_ID);

    public static final UpfMeter SLICE_METER = UpfMeter.builder()
            .setSlice()
            .setCellId(METER_CELL_ID)
            .setPeakBand(PIR, PBURST)
            .build();

    public static final UpfMeter SLICE_METER_RESET = UpfMeter.resetSlice(METER_CELL_ID);

    public static final FlowRule FABRIC_INGRESS_GTP_TUNNEL_PEER = DefaultFlowRule.builder()
            .forDevice(DEVICE_ID).fromApp(APP_ID).makePermanent()
            .forTable(FABRIC_INGRESS_UPF_IG_TUNNEL_PEERS)
            .withSelector(DefaultTrafficSelector.builder()
                    .matchPi(PiCriterion.builder()
                            .matchExact(HDR_TUN_PEER_ID, ENB_GTP_TUNNEL_PEER)
                            .build()).build())
            .withTreatment(DefaultTrafficTreatment.builder()
                    .piTableAction(
                            PiAction.builder()
                                    .withId(FABRIC_INGRESS_UPF_SET_ROUTING_IPV4_DST)
                                    .withParameter(new PiActionParam(TUN_DST_ADDR, ENB_ADDR.toInt()))
                                    .build()).build())
            .withPriority(DEFAULT_PRIORITY)
            .build();

    public static final FlowRule FABRIC_EGRESS_GTP_TUNNEL_PEER = DefaultFlowRule.builder()
            .forDevice(DEVICE_ID).fromApp(APP_ID).makePermanent()
            .forTable(FABRIC_EGRESS_UPF_EG_TUNNEL_PEERS)
            .withSelector(DefaultTrafficSelector.builder()
                    .matchPi(PiCriterion.builder()
                            .matchExact(HDR_TUN_PEER_ID, ENB_GTP_TUNNEL_PEER)
                            .build()).build())
            .withTreatment(DefaultTrafficTreatment.builder()
                    .piTableAction(
                            PiAction.builder()
                                    .withId(FABRIC_EGRESS_UPF_LOAD_TUNNEL_PARAMS)
                                    .withParameters(Arrays.asList(
                                            new PiActionParam(TUNNEL_SRC_ADDR, N3_ADDR.toInt()),
                                            new PiActionParam(TUNNEL_DST_ADDR, ENB_ADDR.toInt()),
                                            new PiActionParam(TUNNEL_SRC_PORT, TUNNEL_SPORT)
                                    ))
                                    .build()).build())
            .withPriority(DEFAULT_PRIORITY)
            .build();

    public static final FlowRule FABRIC_UPLINK_UE_SESSION = DefaultFlowRule.builder()
            .forDevice(DEVICE_ID).fromApp(APP_ID).makePermanent()
            .forTable(FABRIC_INGRESS_UPF_UPLINK_SESSIONS)
            .withSelector(DefaultTrafficSelector.builder()
                                    .matchPi(PiCriterion.builder()
                                            .matchExact(HDR_TEID, TEID_VALUE)
                                            .matchExact(HDR_TUNNEL_IPV4_DST, N3_ADDR.toInt())
                                            .build()).build())
            .withTreatment(DefaultTrafficTreatment.builder()
                    .piTableAction(PiAction.builder()
                            .withId(FABRIC_INGRESS_UPF_SET_UPLINK_SESSION)
                            .withParameter(new PiActionParam(SESSION_METER_IDX, (short) METER_CELL_ID))
                            .build()).build())
            .withPriority(DEFAULT_PRIORITY)
            .build();

    public static final FlowRule FABRIC_DOWNLINK_UE_SESSION = DefaultFlowRule.builder()
            .forDevice(DEVICE_ID).fromApp(APP_ID).makePermanent()
            .forTable(FABRIC_INGRESS_UPF_DOWNLINK_SESSIONS)
            .withSelector(DefaultTrafficSelector.builder()
                    .matchPi(PiCriterion.builder()
                            .matchExact(HDR_UE_ADDR, UE_ADDR.toOctets())
                            .build()).build())
            .withTreatment(DefaultTrafficTreatment.builder()
                    .piTableAction(
                            PiAction.builder()
                                    .withId(FABRIC_INGRESS_UPF_SET_DOWNLINK_SESSION)
                                    .withParameter(new PiActionParam(TUN_PEER_ID, ENB_GTP_TUNNEL_PEER))
                                    .withParameter(new PiActionParam(SESSION_METER_IDX, (short) METER_CELL_ID))
                                    .build()).build())
            .withPriority(DEFAULT_PRIORITY)
            .build();

    public static final FlowRule FABRIC_DOWNLINK_UE_SESSION_DBUF = DefaultFlowRule.builder()
            .forDevice(DEVICE_ID).fromApp(APP_ID).makePermanent()
            .forTable(FABRIC_INGRESS_UPF_DOWNLINK_SESSIONS)
            .withSelector(DefaultTrafficSelector.builder()
                                  .matchPi(PiCriterion.builder()
                                                   .matchExact(HDR_UE_ADDR, UE_ADDR.toInt())
                                                   .build()).build())
            .withTreatment(
                    DefaultTrafficTreatment.builder()
                            .piTableAction(
                                    PiAction.builder()
                                            .withId(FABRIC_INGRESS_UPF_SET_DOWNLINK_SESSION_BUF)
                                            .withParameter(new PiActionParam(TUN_PEER_ID, DBUF_TUNNEL_PEER))
                                            .withParameter(new PiActionParam(SESSION_METER_IDX, (short) METER_CELL_ID))
                                            .build()).build())
            .withPriority(DEFAULT_PRIORITY)
            .build();

    public static final FlowRule FABRIC_UPLINK_UPF_TERMINATION = DefaultFlowRule.builder()
            .forDevice(DEVICE_ID).fromApp(APP_ID).makePermanent()
            .forTable(FABRIC_INGRESS_UPF_UPLINK_TERMINATIONS)
            .withSelector(DefaultTrafficSelector.builder()
                    .matchPi(PiCriterion.builder()
                            // we don't match on slice_id, because we assume distinct UE pools per slice
                            .matchExact(HDR_UE_SESSION_ID, UE_ADDR.toInt())
                            .matchExact(HDR_APP_ID, APP_FILTERING_ID)
                            .build()).build())
            .withTreatment(DefaultTrafficTreatment.builder()
                    .piTableAction(PiAction.builder()
                            .withId(FABRIC_INGRESS_UPF_APP_FWD)
                            .withParameters(Arrays.asList(
                                    new PiActionParam(CTR_ID, UPLINK_COUNTER_CELL_ID),
                                    new PiActionParam(TC, UPLINK_TC),
                                    new PiActionParam(APP_METER_IDX, (short) METER_CELL_ID)
                            ))
                            .build()).build())
            .withPriority(DEFAULT_PRIORITY)
            .build();

    public static final FlowRule FABRIC_UPLINK_UPF_TERMINATION_DROP = DefaultFlowRule.builder()
            .forDevice(DEVICE_ID).fromApp(APP_ID).makePermanent()
            .forTable(FABRIC_INGRESS_UPF_UPLINK_TERMINATIONS)
            .withSelector(DefaultTrafficSelector.builder()
                      .matchPi(PiCriterion.builder()
                               // we don't match on slice_id, because we assume distinct UE pools per slice
                               .matchExact(HDR_UE_SESSION_ID, UE_ADDR.toInt())
                               .matchExact(HDR_APP_ID, DEFAULT_APP_ID)
                               .build()).build())
            .withTreatment(DefaultTrafficTreatment.builder()
                                   .piTableAction(PiAction.builder()
                                                          .withId(FABRIC_INGRESS_UPF_UPLINK_DROP)
                                                          .withParameters(Arrays.asList(
                                                                  new PiActionParam(CTR_ID, UPLINK_COUNTER_CELL_ID)
                                                          ))
                                                          .build()).build())
            .withPriority(DEFAULT_PRIORITY)
            .build();

    public static final FlowRule FABRIC_DOWNLINK_UPF_TERMINATION = DefaultFlowRule.builder()
            .forDevice(DEVICE_ID).fromApp(APP_ID).makePermanent()
            .forTable(FABRIC_INGRESS_UPF_DOWNLINK_TERMINATIONS)
            .withSelector(DefaultTrafficSelector.builder()
                    .matchPi(PiCriterion.builder()
                            // we don't match on slice_id, because we assume distinct UE pools per slice
                            .matchExact(HDR_UE_SESSION_ID, UE_ADDR.toInt())
                            .matchExact(HDR_APP_ID, APP_FILTERING_ID)
                            .build()).build())
            .withTreatment(DefaultTrafficTreatment.builder()
                    .piTableAction(PiAction.builder()
                            .withId(FABRIC_INGRESS_UPF_DOWNLINK_FWD_ENCAP)
                            .withParameters(Arrays.asList(
                                    new PiActionParam(CTR_ID, DOWNLINK_COUNTER_CELL_ID),
                                    new PiActionParam(TC, DOWNLINK_TC),
                                    new PiActionParam(TEID, TEID_VALUE_QOS),
                                    new PiActionParam(QFI, DOWNLINK_QFI),  // 5G case
                                    new PiActionParam(APP_METER_IDX, (short) METER_CELL_ID)
                            ))
                            .build()).build())
            .withPriority(DEFAULT_PRIORITY)
            .build();

    public static final FlowRule FABRIC_DOWNLINK_UPF_TERMINATION_DROP = DefaultFlowRule.builder()
            .forDevice(DEVICE_ID).fromApp(APP_ID).makePermanent()
            .forTable(FABRIC_INGRESS_UPF_DOWNLINK_TERMINATIONS)
            .withSelector(DefaultTrafficSelector.builder()
                      .matchPi(PiCriterion.builder()
                               // we don't match on slice_id, because we assume distinct UE pools per slice
                               .matchExact(HDR_UE_SESSION_ID, UE_ADDR.toInt())
                               .matchExact(HDR_APP_ID, DEFAULT_APP_ID)
                               .build()).build())
            .withTreatment(DefaultTrafficTreatment.builder()
                                   .piTableAction(PiAction.builder()
                                                          .withId(FABRIC_INGRESS_UPF_DOWNLINK_DROP)
                                                          .withParameters(Arrays.asList(
                                                                  new PiActionParam(CTR_ID, DOWNLINK_COUNTER_CELL_ID)
                                                          ))
                                                          .build()).build())
            .withPriority(DEFAULT_PRIORITY)
            .build();

    public static final FlowRule FABRIC_UPLINK_INTERFACE = DefaultFlowRule.builder()
            .forDevice(DEVICE_ID).fromApp(APP_ID).makePermanent()
            .forTable(FABRIC_INGRESS_UPF_INTERFACES)
            .withSelector(DefaultTrafficSelector.builder()
                                  .matchPi(PiCriterion.builder()
                                                   .matchLpm(HDR_IPV4_DST_ADDR,
                                                             N3_ADDR.toInt(),
                                                             32)
                                                   .matchExact(HDR_GTPU_IS_VALID, 1)
                                                   .build()).build())
            .withTreatment(
                    DefaultTrafficTreatment.builder()
                            .piTableAction(
                                    PiAction.builder()
                                            .withId(FABRIC_INGRESS_UPF_IFACE_ACCESS)
                                            .withParameter(new PiActionParam(SLICE_ID, SLICE_MOBILE))
                                            .build()).build())
            .withPriority(DEFAULT_PRIORITY)
            .build();

    public static final FlowRule FABRIC_DOWNLINK_INTERFACE = DefaultFlowRule.builder()
            .forDevice(DEVICE_ID).fromApp(APP_ID).makePermanent()
            .forTable(FABRIC_INGRESS_UPF_INTERFACES)
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
                                                   .withId(FABRIC_INGRESS_UPF_IFACE_CORE)
                                                   .withParameter(new PiActionParam(SLICE_ID, SLICE_MOBILE))
                                                   .build()).build())
            .withPriority(DEFAULT_PRIORITY)
            .build();

    public static final FlowRule FABRIC_APPLICATION_FILTERING = DefaultFlowRule.builder()
            .forDevice(DEVICE_ID).fromApp(APP_ID).makePermanent()
            .forTable(FABRIC_INGRESS_UPF_APPLICATIONS)
            .withSelector(
                    DefaultTrafficSelector.builder()
                            .matchPi(PiCriterion.builder()
                                             .matchExact(HDR_SLICE_ID, SLICE_MOBILE)
                                             .matchLpm(HDR_APP_IPV4_ADDR,
                                                       APP_IP_PREFIX.address().toOctets(),
                                                       APP_IP_PREFIX.prefixLength())
                                             .matchRange(HDR_APP_L4_PORT,
                                                         APP_L4_RANGE.getLeft(),
                                                         APP_L4_RANGE.getRight())
                                             .matchTernary(HDR_APP_IP_PROTO,
                                                           APP_IP_PROTO,
                                                           0xF)
                                             .build()).build())
            .withTreatment(
                    DefaultTrafficTreatment.builder().piTableAction(
                            PiAction.builder()
                                    .withId(FABRIC_INGRESS_UPF_SET_APP_ID)
                                    .withParameter(new PiActionParam(
                                            P4InfoConstants.APP_ID, APP_FILTERING_ID))
                                    .build()).build())
            .withPriority(APP_FILTERING_PRIORITY)
            .build();

    public static final Meter FABRIC_SESSION_METER = DefaultMeter.builder()
            .forDevice(DEVICE_ID).fromApp(APP_ID)
            .withCellId(PiMeterCellId.ofIndirect(FABRIC_INGRESS_UPF_SESSION_METER, METER_CELL_ID))
            .withBands(Lists.newArrayList(
                    DefaultBand.builder().ofType(Band.Type.MARK_RED).withRate(PIR).burstSize(PBURST).build(),
                    DefaultBand.builder().ofType(Band.Type.MARK_YELLOW).withRate(0).burstSize(0).build()
            ))
            .withUnit(BYTES_PER_SEC)
            .build();

    public static final MeterRequest FABRIC_SESSION_METER_REQUEST = DefaultMeterRequest.builder()
            .forDevice(DEVICE_ID).fromApp(APP_ID)
            .withIndex((long) METER_CELL_ID)
            .withScope(MeterScope.of(FABRIC_INGRESS_UPF_SESSION_METER.id()))
            .withUnit(BYTES_PER_SEC)
            .withBands(Lists.newArrayList(
                    DefaultBand.builder().ofType(Band.Type.MARK_RED).withRate(PIR).burstSize(PBURST).build(),
                    DefaultBand.builder().ofType(Band.Type.MARK_YELLOW).withRate(0).burstSize(0).build()
            ))
            .add();

    public static final MeterRequest FABRIC_SESSION_METER_RESET_REQUEST = DefaultMeterRequest.builder()
            .forDevice(DEVICE_ID).fromApp(APP_ID)
            .withIndex((long) METER_CELL_ID)
            .withScope(MeterScope.of(FABRIC_INGRESS_UPF_SESSION_METER.id()))
            .withUnit(BYTES_PER_SEC)
            .remove();

    public static final Meter FABRIC_APP_METER = DefaultMeter.builder()
            .forDevice(DEVICE_ID).fromApp(APP_ID)
            .withCellId(PiMeterCellId.ofIndirect(FABRIC_INGRESS_UPF_APP_METER, METER_CELL_ID))
            .withBands(Lists.newArrayList(
                    DefaultBand.builder().ofType(Band.Type.MARK_RED).withRate(PIR).burstSize(PBURST).build(),
                    DefaultBand.builder().ofType(Band.Type.MARK_YELLOW).withRate(CIR).burstSize(CBURST).build()
            ))
            .withUnit(BYTES_PER_SEC)
            .build();

    public static final MeterRequest FABRIC_APP_METER_REQUEST = DefaultMeterRequest.builder()
            .forDevice(DEVICE_ID).fromApp(APP_ID)
            .withIndex((long) METER_CELL_ID)
            .withScope(MeterScope.of(FABRIC_INGRESS_UPF_APP_METER.id()))
            .withUnit(BYTES_PER_SEC)
            .withBands(Lists.newArrayList(
                    DefaultBand.builder().ofType(Band.Type.MARK_RED).withRate(PIR).burstSize(PBURST).build(),
                    DefaultBand.builder().ofType(Band.Type.MARK_YELLOW).withRate(CIR).burstSize(CBURST).build()
            ))
            .add();

    public static final MeterRequest FABRIC_APP_METER_RESET_REQUEST = DefaultMeterRequest.builder()
            .forDevice(DEVICE_ID).fromApp(APP_ID)
            .withIndex((long) METER_CELL_ID)
            .withScope(MeterScope.of(FABRIC_INGRESS_UPF_APP_METER.id()))
            .withUnit(BYTES_PER_SEC)
            .remove();

    public static final Meter FABRIC_SLICE_METER = DefaultMeter.builder()
            .forDevice(DEVICE_ID).fromApp(APP_ID)
            .withCellId(PiMeterCellId.ofIndirect(FABRIC_INGRESS_QOS_SLICE_TC_METER, METER_CELL_ID))
            .withBands(Lists.newArrayList(
                    DefaultBand.builder().ofType(Band.Type.MARK_RED).withRate(PIR).burstSize(PBURST).build(),
                    DefaultBand.builder().ofType(Band.Type.MARK_YELLOW).withRate(0).burstSize(0).build()
            ))
            .withUnit(BYTES_PER_SEC)
            .build();

    public static final MeterRequest FABRIC_SLICE_METER_REQUEST = DefaultMeterRequest.builder()
            .forDevice(DEVICE_ID).fromApp(APP_ID)
            .withIndex((long) METER_CELL_ID)
            .withScope(MeterScope.of(FABRIC_INGRESS_QOS_SLICE_TC_METER.id()))
            .withUnit(BYTES_PER_SEC)
            .withBands(Lists.newArrayList(
                    DefaultBand.builder().ofType(Band.Type.MARK_RED).withRate(PIR).burstSize(PBURST).build(),
                    DefaultBand.builder().ofType(Band.Type.MARK_YELLOW).withRate(0).burstSize(0).build()
            ))
            .add();

    public static final MeterRequest FABRIC_SLICE_METER_RESET_REQUEST = DefaultMeterRequest.builder()
            .forDevice(DEVICE_ID).fromApp(APP_ID)
            .withIndex((long) METER_CELL_ID)
            .withScope(MeterScope.of(FABRIC_INGRESS_QOS_SLICE_TC_METER.id()))
            .withUnit(BYTES_PER_SEC)
            .remove();

    /**
     * Hidden constructor for utility class.
     */
    private TestUpfConstants() {
    }
}
