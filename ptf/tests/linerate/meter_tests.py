# SPDX-FileCopyrightText: Copyright 2022-present Open Networking Foundation.
# SPDX-License-Identifier: Apache-2.0

# This file contains line rate tests checking that the color-aware meters used
# in the pipeline works as expected.

import qos_utils
from base_test import *
from fabric_test import *
from ptf.testutils import group, simple_udp_packet
from trex_stl_lib.api import STLFlowLatencyStats, STLPktBuilder, STLStream, STLTXCont
from trex_test import TRexTest
from trex_utils import *

SEPARATOR = "======================================"

TRAFFIC_DURATION_SECONDS = 10

ALL_PORTS = [0, 1, 2, 3]

N3_ADDR = "140.0.0.2"
ENB_IPV4 = "119.0.0.10"
UPF_CTR_IDX = 10
UE_1_UL_APP1_METER_IDX = 10
UE_1_UL_APP2_METER_IDX = 20
UE_2_UL_APP_METER_IDX = 11
UE_1_UL_SESSION_METER_IDX = 10
UE_2_UL_SESSION_METER_IDX = 11
UE1_ADDR = "10.0.0.1"
UE2_ADDR = "10.0.0.2"
UE1_UL_TEID = 0xEEFFC0F0
UE2_UL_TEID = 0xEEFFC0F1
APP1_PORT = 100
APP2_PORT = 200
APP1_ID = 10
APP2_ID = 20

# All these tests require software mode
# TREX_PARAMS="--trex-sw-mode" ./ptf/run/hw/linerate fabric-upf-int


class UpfPolicingTest(TRexTest, UpfSimpleTest, StatsTest):

    def setup_queues_table(self):
        """
        Setup the queue table to map GREEN and YELLOW traffic of the default slice
        and default TC to the best effort queue, while dropping RED traffic.
        :return:
        """
        # Default TC to BE queue + drop RED traffic
        self.add_queue_entry(DEFAULT_SLICE_ID, DEFAULT_TC, qid=qos_utils.QUEUE_ID_BEST_EFFORT, color=COLOR_GREEN)
        self.add_queue_entry(DEFAULT_SLICE_ID, DEFAULT_TC, qid=qos_utils.QUEUE_ID_BEST_EFFORT, color=COLOR_YELLOW)
        self.enable_policing(DEFAULT_SLICE_ID, DEFAULT_TC)

    def setup_slice(self, slice_rate):
        """
        Setup slice level tables and meter (interface table + slice meter).
        :param slice_rate:
        :return:
        """
        # Slice level configuration
        self.add_s1u_iface(s1u_addr=N3_ADDR, slice_id=DEFAULT_SLICE_ID)
        self.add_slice_tc_meter(slice_id=DEFAULT_SLICE_ID, tc=DEFAULT_TC, committed_rate=1, peak_rate=slice_rate)

    def setup_ue_ul(
            self, ue_addr, ul_teid, app_meter_idx=DEFAULT_APP_METER_IDX, app_meter_bps=None,
            sess_meter_idx=DEFAULT_SESSION_METER_IDX, session_meter_bps=None, app_id=NO_APP_ID
    ) -> None:
        """
        Setup UE uplink table entries (UL session and UL termination) and eventually
        the session meter and app meter.
        :param ue_addr:
        :param ul_teid:
        :param app_meter_idx:
        :param app_meter_bps:
        :param sess_meter_idx:
        :param session_meter_bps:
        :param app_id:
        :return:
        """
        if sess_meter_idx != DEFAULT_SESSION_METER_IDX and session_meter_bps is not None:
            self.add_qer_session_meter(sess_meter_idx, session_meter_bps)
        if app_meter_idx != DEFAULT_APP_METER_IDX and app_meter_bps is not None:
            self.add_qer_app_meter(app_meter_idx, app_meter_bps)
        self.setup_uplink_ue_session(
            teid=ul_teid, tunnel_dst_addr=N3_ADDR, session_meter_idx=sess_meter_idx
        )
        self.setup_uplink_termination(
            ue_session=ue_addr, ctr_id=UPF_CTR_IDX, tc=DEFAULT_TC, app_id=app_id,
            app_meter_idx=app_meter_idx
        )

    def setup_acl_forwarding(self, in_ports, out_port) -> None:
        """
        Setup ACL table to perform forwarding based on input ports.
        :param in_ports:
        :param out_port:
        :return:
        """
        # Setup ingress port VLAN table to let traffic into the pipeline
        for port in set(in_ports + [out_port]):
            self.setup_port(port, DEFAULT_VLAN, PORT_TYPE_EDGE)
        # Do actual forwarding via ACL
        for in_port in in_ports:
            self.add_forwarding_acl_set_output_port(out_port, ig_port=in_port)

    # Create a stream with GTP encapped traffic.
    def create_gtp_stream(
            self, ue_addr, teid, pg_id=None, dport=None, l2_size=None, l1_bps=None,
    ) -> STLStream:
        if dport is not None:
            pkt = simple_udp_packet(ip_src=ue_addr, pktlen=l2_size - GTPU_HDR_BYTES, udp_dport=dport)
        else:
            pkt = simple_udp_packet(ip_src=ue_addr, pktlen=l2_size - GTPU_HDR_BYTES)
        pkt = pkt_add_gtp(pkt, out_ipv4_src=ENB_IPV4, out_ipv4_dst=N3_ADDR, teid=teid)
        stats = None
        if pg_id is not None:
            stats = STLFlowLatencyStats(pg_id=pg_id)
        return STLStream(
            packet=STLPktBuilder(pkt=pkt),
            mode=STLTXCont(bps_L1=l1_bps),
            flow_stats=stats,
        )

    def average_monitored_port_stats(self, stats):
        """
        Average the stats captured live removing the first and last sample that might
        be inaccurate.
        :param stats:
        :return: dictionary with per port average TX and average RX
        """
        # Average the live stats, removing first and last sample that might be inaccurate
        avg_tx = [sum(v["tx_bps"][1:-1]) / (len(v["tx_bps"])-2)
                  for (k, v) in stats.items()if k != "duration"]
        avg_rx =[sum(v["rx_bps"][1:-1]) / (len(v["rx_bps"])-2)
                 for (k, v) in stats.items() if k != "duration"]
        return {"avg_tx": avg_tx, "avg_rx": avg_rx}


@group("trex-sw-mode")
@group("upf")
@group("meter")
class AppLevelPolicing(UpfPolicingTest):
    """
    Verify the behaviour of the application level policing.
    """
    def __init__(self):
        super().__init__()

    @autocleanup
    def runTest(self) -> None:
        app_rate = 100 * M
        session_rate = 200 * M
        slice_rate = 200 * M

        self.push_chassis_config()
        self.setup_queues_table()
        self.setup_slice(slice_rate)
        # Setup ACL forwarding
        self.setup_acl_forwarding(in_ports=[self.port3], out_port=self.port2)
        # Configure common application between the two UEs
        self.setup_app_filtering(APP1_ID, slice_id=DEFAULT_SLICE_ID, l4_port=APP1_PORT)

        # UE 1 configuration
        self.setup_ue_ul(
            ue_addr=UE1_ADDR,
            ul_teid=UE1_UL_TEID,
            app_id=APP1_ID,
            app_meter_idx=UE_1_UL_APP1_METER_IDX,
            app_meter_bps=app_rate,
            sess_meter_idx=UE_1_UL_SESSION_METER_IDX,
            session_meter_bps=session_rate
        )

        # UE 2 configuration
        self.setup_ue_ul(
            ue_addr=UE2_ADDR,
            ul_teid=UE2_UL_TEID,
            app_id=APP1_ID,
            app_meter_idx=UE_2_UL_APP_METER_IDX,
            app_meter_bps=app_rate,
            sess_meter_idx=UE_2_UL_SESSION_METER_IDX,
            session_meter_bps=session_rate
        )

        # UE1 within the APP meter rate
        stream_bps_ue1 = app_rate
        pg_id_ue1 = 1

        # UE2 above the APP meter rate
        stream_bps_ue2 = 2 * app_rate
        pg_id_ue2 = 2

        streams = [self.create_gtp_stream(
                ue_addr=UE1_ADDR, teid=UE1_UL_TEID,
                pg_id=pg_id_ue1, l1_bps=stream_bps_ue1, dport=APP1_PORT, l2_size=1400
            ),
            self.create_gtp_stream(
                ue_addr=UE2_ADDR, teid=UE2_UL_TEID,
                pg_id=pg_id_ue2, l1_bps=stream_bps_ue2, dport=APP1_PORT, l2_size=1400
           )
        ]

        switch_ig_port = self.port3  # Trex port 2
        TREX_OUT_PORT = 2
        switch_eg_port = self.port2  # Trex port 1
        TREX_IN_PORT = 1

        self.trex_client.add_streams(streams, ports=TREX_OUT_PORT)
        print(f"Starting traffic, duration: {TRAFFIC_DURATION_SECONDS} sec")
        self.trex_client.start(TREX_OUT_PORT, duration=TRAFFIC_DURATION_SECONDS)
        live_stats = monitor_port_stats(self.trex_client)
        self.trex_client.wait_on_traffic(ports=TREX_OUT_PORT, rx_delay_ms=100)
        avg_live_stats = self.average_monitored_port_stats(live_stats)

        # Get and print TREX stats
        trex_stats = self.trex_client.get_stats()
        lat_stats_ue1 = get_latency_stats(pg_id_ue1, trex_stats)
        lat_stats_ue2 = get_latency_stats(pg_id_ue2, trex_stats)
        flow_stats_ue1 = get_flow_stats(pg_id_ue1, trex_stats)
        flow_stats_ue2 = get_flow_stats(pg_id_ue2, trex_stats)
        # in_port_stats = get_port_stats(TREX_IN_PORT, trex_stats)

        rx_bps_ue1 = (flow_stats_ue1.rx_bytes * 8) / TRAFFIC_DURATION_SECONDS
        rx_bps_ue2 = (flow_stats_ue2.rx_bytes * 8) / TRAFFIC_DURATION_SECONDS

        print("")
        print("============= STATS UE 1 =============")
        print(get_readable_flow_stats(flow_stats_ue1))
        print(get_readable_latency_stats(lat_stats_ue1))
        print(SEPARATOR)
        print("============= STATS UE 2 =============")
        print(get_readable_flow_stats(flow_stats_ue2))
        print(get_readable_latency_stats(lat_stats_ue2))
        print(SEPARATOR)
        # for port in ALL_PORTS:
        #     readable_stats = get_readable_port_stats(trex_stats[port])
        #     print("Statistics for port {}: {}".format(port, readable_stats))

        # No dropped packets for conforming traffic
        self.assertEqual(
            lat_stats_ue1.dropped,
            0,
            "Conforming traffic shouldn't get packet drops"
        )
        # Dropped packets for flow over the application meter rate
        self.assertGreater(
            lat_stats_ue2.dropped,
            0,
            "Misbehaving traffic should get packet drops"
        )
        self.assertAlmostEqual(
            rx_bps_ue1 / app_rate,
            1,
            delta=0.05,
            msg="UE 1 traffic should be almost equal to the app rate"
        )
        self.assertAlmostEqual(
            rx_bps_ue2 / app_rate,
            1,
            delta=0.05,
            msg="UE 2 traffic should be almost equal to the app rate"
        )
        self.assertAlmostEqual(
            # 2 Flows, we expect twice the expected rate
            avg_live_stats["avg_rx"][TREX_IN_PORT] / (2 * app_rate),
            1,
            delta=0.1,
            msg="Traffic should be almost equal to twice the app rate"
        )


@group("trex-sw-mode")
@group("upf")
@group("meter")
class SessionLevelPolicing(UpfPolicingTest):
    def __init__(self):
        super().__init__()

    @autocleanup
    def runTest(self) -> None:
        session_rate = 100 * M
        slice_rate = 200 * M

        switch_ig_port = self.port3  # Trex port 2
        TREX_OUT_PORT = 2
        switch_eg_port = self.port2  # Trex port 1
        TREX_IN_PORT = 1

        self.push_chassis_config()
        self.setup_queues_table()
        self.setup_slice(slice_rate)
        # Setup ACL forwarding
        self.setup_acl_forwarding(in_ports=[switch_ig_port], out_port=switch_eg_port)

        # UE 1 configuration
        self.setup_ue_ul(
            ue_addr=UE1_ADDR,
            ul_teid=UE1_UL_TEID,
            sess_meter_idx=UE_1_UL_SESSION_METER_IDX,
            session_meter_bps=session_rate,
        )

        # UE 2 configuration
        self.setup_ue_ul(
            ue_addr=UE2_ADDR,
            ul_teid=UE2_UL_TEID,
            sess_meter_idx=UE_2_UL_SESSION_METER_IDX,
            session_meter_bps=session_rate
        )

        # UE1 within the session meter rate
        stream_bps_ue1 = session_rate
        pg_id_ue1 = 1
        # UE2 above the session meter rate
        stream_bps_ue2 = 2 * session_rate
        pg_id_ue2 = 2

        streams = [
            self.create_gtp_stream(
                ue_addr=UE1_ADDR, teid=UE1_UL_TEID,
                pg_id=pg_id_ue1, l1_bps=stream_bps_ue1, l2_size=1400
            ),
            self.create_gtp_stream(
                ue_addr=UE2_ADDR, teid=UE2_UL_TEID,
                pg_id=pg_id_ue2, l1_bps=stream_bps_ue2, l2_size=1400
            )
        ]

        self.trex_client.add_streams(streams, ports=TREX_OUT_PORT)
        print(f"Starting traffic, duration: {TRAFFIC_DURATION_SECONDS} sec")
        self.trex_client.start(TREX_OUT_PORT, duration=TRAFFIC_DURATION_SECONDS)
        live_stats = monitor_port_stats(self.trex_client)
        self.trex_client.wait_on_traffic(ports=TREX_OUT_PORT, rx_delay_ms=100)
        avg_live_stats = self.average_monitored_port_stats(live_stats)

        # Get and print TREX stats
        trex_stats = self.trex_client.get_stats()
        lat_stats_ue1 = get_latency_stats(pg_id_ue1, trex_stats)
        lat_stats_ue2 = get_latency_stats(pg_id_ue2, trex_stats)
        flow_stats_ue1 = get_flow_stats(pg_id_ue1, trex_stats)
        flow_stats_ue2 = get_flow_stats(pg_id_ue2, trex_stats)
        # in_port_stats = get_port_stats(TREX_IN_PORT, trex_stats)

        rx_bps_ue1 = (flow_stats_ue1.rx_bytes * 8) / TRAFFIC_DURATION_SECONDS
        rx_bps_ue2 = (flow_stats_ue2.rx_bytes * 8) / TRAFFIC_DURATION_SECONDS

        print("============= STATS UE 1 =============")
        print(get_readable_flow_stats(flow_stats_ue1))
        print(get_readable_latency_stats(lat_stats_ue1))
        print(SEPARATOR)
        print("============= STATS UE 2 =============")
        print(get_readable_flow_stats(flow_stats_ue2))
        print(get_readable_latency_stats(lat_stats_ue2))
        print(SEPARATOR)
        # for port in ALL_PORTS:
        #     readable_stats = get_readable_port_stats(trex_stats[port])
        #     print("Statistics for port {}: {}".format(port, readable_stats))

        # No dropped packets for conforming traffic
        self.assertEqual(
            lat_stats_ue1.dropped,
            0,
            "Conforming traffic shouldn't get packet drops"
        )
        # Dropped packets for flow over the application meter rate
        self.assertGreater(
            lat_stats_ue2.dropped,
            0,
            "Misbehaving traffic should get packet drops"
        )
        self.assertAlmostEqual(
            rx_bps_ue1 / session_rate,
            1,
            delta=0.05,
            msg="UE 1 traffic should be almost equal to the session rate"
        )
        self.assertAlmostEqual(
            rx_bps_ue2 / session_rate,
            1,
            delta=0.05,
            msg="UE 2 traffic should be almost equal to the session rate"
        )
        self.assertAlmostEqual(
            # 2 Flows, we expect twice the expected rate
            avg_live_stats["avg_rx"][TREX_IN_PORT] / (2 * session_rate),
            1,
            delta=0.1,
            msg="Traffic should be almost equal to twice the session rate"
        )


@group("trex-sw-mode")
@group("upf")
@group("meter")
class ColorAwareSliceMeter(UpfPolicingTest):
    """
    Verify the behavior of the color-aware slice meter.
    Session Rate = 80Mbps
    Slice Rate = 100Mbps
    Two flows for different UEs:
     1) conforming to session rate (20Mbps) (flow 1 + session rate = slice rate)
     2) misbehaving, with rate above the session rate (100Mbps)
    Output rate should be equal to the slice rate.
    Flow 1 should not be shaped.
    Flow 2 should be shaped to the session rate.
    Result should output rate should be slice rate.
    """
    def __init__(self):
        super().__init__()

    @autocleanup
    def runTest(self) -> None:
        session_rate = 80 * M
        slice_rate = 100 * M

        switch_ig_port = self.port3  # Trex port 2
        TREX_OUT_PORT = 2
        switch_eg_port = self.port2  # Trex port 1
        TREX_IN_PORT = 1

        self.push_chassis_config()
        self.setup_queues_table()
        self.setup_slice(slice_rate)
        # Setup ACL forwarding
        self.setup_acl_forwarding(in_ports=[switch_ig_port], out_port=switch_eg_port)

        # UE 1 configuration
        self.setup_ue_ul(
            ue_addr=UE1_ADDR,
            ul_teid=UE1_UL_TEID,
            sess_meter_idx=UE_1_UL_SESSION_METER_IDX,
            session_meter_bps=session_rate,
        )

        # UE 2 configuration
        self.setup_ue_ul(
            ue_addr=UE2_ADDR,
            ul_teid=UE2_UL_TEID,
            sess_meter_idx=UE_2_UL_SESSION_METER_IDX,
            session_meter_bps=session_rate,
        )

        # UE1 within the session meter rate
        stream_bps_ue1 = 20 * M
        pg_id_ue1 = 1
        # UE2 above the session meter rate
        stream_bps_ue2 = 100 * M
        pg_id_ue2 = 2

        streams = [
            self.create_gtp_stream(
                ue_addr=UE1_ADDR, teid=UE1_UL_TEID,
                pg_id=pg_id_ue1, l1_bps=stream_bps_ue1, l2_size=1400
            ),
            self.create_gtp_stream(
                ue_addr=UE2_ADDR, teid=UE2_UL_TEID,
                pg_id=pg_id_ue2, l1_bps=stream_bps_ue2, l2_size=1400
            )
        ]

        self.trex_client.add_streams(streams, ports=TREX_OUT_PORT)
        print(f"Starting traffic, duration: {TRAFFIC_DURATION_SECONDS} sec")
        self.trex_client.start(TREX_OUT_PORT, duration=TRAFFIC_DURATION_SECONDS)
        live_stats = monitor_port_stats(self.trex_client)
        self.trex_client.wait_on_traffic(ports=TREX_OUT_PORT, rx_delay_ms=100)
        avg_live_stats = self.average_monitored_port_stats(live_stats)

        # Get and print TREX stats
        trex_stats = self.trex_client.get_stats()
        lat_stats_ue1 = get_latency_stats(pg_id_ue1, trex_stats)
        lat_stats_ue2 = get_latency_stats(pg_id_ue2, trex_stats)
        flow_stats_ue1 = get_flow_stats(pg_id_ue1, trex_stats)
        flow_stats_ue2 = get_flow_stats(pg_id_ue2, trex_stats)

        rx_bps_ue1 = (flow_stats_ue1.rx_bytes * 8) / TRAFFIC_DURATION_SECONDS
        rx_bps_ue2 = (flow_stats_ue2.rx_bytes * 8) / TRAFFIC_DURATION_SECONDS

        print("============= STATS UE 1 =============")
        print(f"   RX Mbps: {rx_bps_ue1/M}")
        print(get_readable_flow_stats(flow_stats_ue1))
        print(get_readable_latency_stats(lat_stats_ue1))
        print(SEPARATOR)
        print("============= STATS UE 2 =============")
        print(f"   RX Mbps: {rx_bps_ue2/M}")
        print(get_readable_flow_stats(flow_stats_ue2))
        print(get_readable_latency_stats(lat_stats_ue2))
        print(SEPARATOR)

        self.assertEqual(
            lat_stats_ue1.dropped,
            0,
            "Conforming traffic shouldn't get packet drops"
        )
        self.assertGreater(
            lat_stats_ue2.dropped,
            0,
            "Misbehaving traffic should get packet drops"
        )
        self.assertAlmostEqual(
            avg_live_stats["avg_rx"][TREX_IN_PORT] / slice_rate,
            1,
            delta=0.1,
            msg="Traffic should be almost equal the slice rate"
        )
        self.assertAlmostEqual(
            rx_bps_ue1 / stream_bps_ue1,
            1,
            delta=0.05,
            msg="UE 1 traffic (same as session rate) should not be shaped"
        )
        self.assertAlmostEqual(
            rx_bps_ue2 / session_rate,
            1,
            delta=0.05,
            msg="UE 2 traffic (above session rate) should be shaped to session rate"
        )


@group("trex-sw-mode")
@group("upf")
@group("meter")
class ColorAwareSessionMeter(UpfPolicingTest):
    """
    Verify the behavior of the color-aware session meter.
    App Rate = 50Mbps
    Session Rate = 80Mbps
    Slice Rate = 200Mbps
    Two flows for different APPs:
     1) conforming to app rate (30Mbps) (flow 1 + app rate = session rate)
     2) misbehaving, with rate above the app rate and session rate (100Mbps)
    Output rate should be equal to the session rate.
    Flow 1 should be not be shaped
    Flow 2 should be shaped to around session rate - flow 1 rate
    Result should output rate should be the session rate.
    """
    def __init__(self):
        super().__init__()

    @autocleanup
    def runTest(self) -> None:
        app_rate = 50 * M
        session_rate = 80 * M
        slice_rate = 200 * M

        switch_ig_port = self.port3  # Trex port 2
        TREX_OUT_PORT = 2
        switch_eg_port = self.port2  # Trex port 1
        TREX_IN_PORT = 1

        self.push_chassis_config()
        self.setup_queues_table()
        self.setup_slice(slice_rate)
        # Setup ACL forwarding
        self.setup_acl_forwarding(in_ports=[switch_ig_port], out_port=switch_eg_port)

        # Single session (UE) with 2 applications
        #  Setup sessions
        self.add_qer_session_meter(UE_1_UL_SESSION_METER_IDX, session_rate)
        self.setup_uplink_ue_session(
            teid=UE1_UL_TEID, tunnel_dst_addr=N3_ADDR, session_meter_idx=UE_1_UL_SESSION_METER_IDX
        )
        #  Application 1
        self.setup_app_filtering(APP1_ID, slice_id=DEFAULT_SLICE_ID, l4_port=APP1_PORT)
        self.add_qer_app_meter(UE_1_UL_APP1_METER_IDX, app_rate)
        self.setup_uplink_termination(
            ue_session=UE1_ADDR, ctr_id=UPF_CTR_IDX, tc=DEFAULT_TC, app_id=APP1_ID,
            app_meter_idx=UE_1_UL_APP1_METER_IDX
        )
        #  Application 2
        self.setup_app_filtering(APP2_ID, slice_id=DEFAULT_SLICE_ID, l4_port=APP2_PORT)
        self.add_qer_app_meter(UE_1_UL_APP2_METER_IDX, app_rate)
        self.setup_uplink_termination(
            ue_session=UE1_ADDR, ctr_id=UPF_CTR_IDX, tc=DEFAULT_TC, app_id=APP2_ID,
            app_meter_idx=UE_1_UL_APP2_METER_IDX
        )

        # UE1 - APP1 within the session meter rate
        stream_bps_app1 = 30 * M
        pg_id_app1 = 1
        # UE1 - APP2 above the session meter rate
        stream_bps_app2 = 100 * M
        pg_id_app2 = 2

        streams = [
            self.create_gtp_stream(
                ue_addr=UE1_ADDR, teid=UE1_UL_TEID,
                pg_id=pg_id_app1, l1_bps=stream_bps_app1, dport=APP1_PORT, l2_size=1400
            ),
            self.create_gtp_stream(
                ue_addr=UE1_ADDR, teid=UE1_UL_TEID,
                pg_id=pg_id_app2, l1_bps=stream_bps_app2, dport=APP2_PORT, l2_size=1400
            )
        ]

        self.trex_client.add_streams(streams, ports=TREX_OUT_PORT)
        print(f"Starting traffic, duration: {TRAFFIC_DURATION_SECONDS} sec")
        self.trex_client.start(TREX_OUT_PORT, duration=TRAFFIC_DURATION_SECONDS)
        live_stats = monitor_port_stats(self.trex_client)
        self.trex_client.wait_on_traffic(ports=TREX_OUT_PORT, rx_delay_ms=100)
        avg_live_stats = self.average_monitored_port_stats(live_stats)

        # Get and print TREX stats
        trex_stats = self.trex_client.get_stats()
        lat_stats_app1 = get_latency_stats(pg_id_app1, trex_stats)
        lat_stats_app2 = get_latency_stats(pg_id_app2, trex_stats)
        flow_stats_app1 = get_flow_stats(pg_id_app1, trex_stats)
        flow_stats_app2 = get_flow_stats(pg_id_app2, trex_stats)

        rx_bps_app1 = (flow_stats_app1.rx_bytes * 8) / TRAFFIC_DURATION_SECONDS
        rx_bps_app2 = (flow_stats_app2.rx_bytes * 8) / TRAFFIC_DURATION_SECONDS

        print("============= STATS APP 1 =============")
        print(f"   RX Mbps: {rx_bps_app1/M}")
        print(get_readable_flow_stats(flow_stats_app1))
        print(get_readable_latency_stats(lat_stats_app1))
        print(SEPARATOR)
        print("============= STATS APP 2 =============")
        print(f"   RX Mbps: {rx_bps_app2/M}")
        print(get_readable_flow_stats(flow_stats_app2))
        print(get_readable_latency_stats(lat_stats_app2))
        print(SEPARATOR)

        self.assertEqual(
            lat_stats_app1.dropped,
            0,
            "Conforming traffic shouldn't get packet drops"
        )
        self.assertGreater(
            lat_stats_app2.dropped,
            0,
            "Misbehaving traffic should get packet drops"
        )
        self.assertAlmostEqual(
            avg_live_stats["avg_rx"][TREX_IN_PORT] / session_rate,
            1,
            delta=0.1,
            msg="Traffic should be almost equal to the session rate"
        )
        self.assertAlmostEqual(
            rx_bps_app1 / stream_bps_app1,
            1,
            delta=0.05,
            msg="APP 1 traffic (below app rate) should not be shaped"
        )
        self.assertAlmostEqual(
            rx_bps_app2 / app_rate,
            1,
            delta=0.05,
            msg="APP 2 traffic (above app rate) should be shaped to app rate"
        )
