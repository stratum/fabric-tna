# SPDX-FileCopyrightText: Copyright 2022-present Open Networking Foundation.
# SPDX-License-Identifier: Apache-2.0

# This file contains line rate tests checking that the color-aware meters used
# in the pipeline works as expected.
# All these tests require software mode
# TREX_PARAMS="--trex-sw-mode" ./ptf/run/hw/linerate fabric-upf-int TEST=meter_tests

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


class UpfPolicingTest(TRexTest, UpfSimpleTest, StatsTest):
    def setup_queues_table(self):
        """
        Setup the queue table to map GREEN and YELLOW traffic of the default slice
        and default TC to the best effort queue, while dropping RED traffic.
        :return:
        """
        # Default TC to BE queue + drop RED traffic
        self.add_queue_entry(
            DEFAULT_SLICE_ID,
            DEFAULT_TC,
            qid=qos_utils.QUEUE_ID_BEST_EFFORT,
            color=COLOR_GREEN,
        )
        self.add_queue_entry(
            DEFAULT_SLICE_ID,
            DEFAULT_TC,
            qid=qos_utils.QUEUE_ID_BEST_EFFORT,
            color=COLOR_YELLOW,
        )
        self.enable_policing(DEFAULT_SLICE_ID, DEFAULT_TC)

    def setup_slice(self, slice_bps):
        """
        Setup slice level tables and meter (interface table + slice meter).
        :param slice_bps:
        :return:
        """
        # Slice level configuration
        self.add_s1u_iface(s1u_addr=N3_ADDR, slice_id=DEFAULT_SLICE_ID)
        self.add_slice_tc_meter(
            slice_id=DEFAULT_SLICE_ID,
            tc=DEFAULT_TC,
            committed_bps=1,
            peak_bps=slice_bps,
        )

    def setup_ue_ul(
        self,
        ue_addr,
        ul_teid,
        app_meter_idx=DEFAULT_APP_METER_IDX,
        app_meter_bps=None,
        sess_meter_idx=DEFAULT_SESSION_METER_IDX,
        session_meter_bps=None,
        app_id=NO_APP_ID,
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
        if (
            sess_meter_idx != DEFAULT_SESSION_METER_IDX
            and session_meter_bps is not None
        ):
            self.add_qer_session_meter(sess_meter_idx, session_meter_bps)
        if app_meter_idx != DEFAULT_APP_METER_IDX and app_meter_bps is not None:
            self.add_qer_app_meter(app_meter_idx, app_meter_bps)
        self.setup_uplink_ue_session(
            teid=ul_teid, tunnel_dst_addr=N3_ADDR, session_meter_idx=sess_meter_idx
        )
        self.setup_uplink_termination(
            ue_session=ue_addr,
            ctr_id=UPF_CTR_IDX,
            tc=DEFAULT_TC,
            app_id=app_id,
            app_meter_idx=app_meter_idx,
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
        self, ue_addr, teid, pg_id=None, dport=None, l2_size=1400, l1_bps=None,
    ) -> STLStream:
        if dport is not None:
            pkt = simple_udp_packet(
                ip_src=ue_addr, pktlen=l2_size - GTPU_HDR_BYTES, udp_dport=dport
            )
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

    def min_max_monitored_port_stats(self, stats) -> {}:
        """
        Minimum and maximum of the TX/RX stats captured live, obtained removing
        the first and last sample that might be inaccurate due to rump up and down
        of traffic from TRex.
        :param stats:
        :return: dictionary with per port min and max TX/RX
        """
        min_tx = [min(v["tx_bps"][1:-1]) for (k, v) in stats.items() if k != "duration"]
        max_tx = [max(v["tx_bps"][1:-1]) for (k, v) in stats.items() if k != "duration"]
        min_rx = [min(v["rx_bps"][1:-1]) for (k, v) in stats.items() if k != "duration"]
        max_rx = [max(v["rx_bps"][1:-1]) for (k, v) in stats.items() if k != "duration"]
        return {"min_tx": min_tx, "max_tx": max_tx, "min_rx": min_rx, "max_rx": max_rx}


@group("trex-sw-mode")
@group("upf")
class UpfAppOnlyPolicingTest(UpfPolicingTest):
    """
    Verify the behaviour of application level policing.
    Flows above the app rate should be policed, flows below the app rate shouldn't.
    """

    @autocleanup
    def runTest(self) -> None:
        app_bps = 100 * M
        session_bps = 200 * M
        slice_bps = 200 * M
        # UE1 within the APP meter rate
        stream_bps_ue1 = app_bps
        pg_id_ue1 = 1
        # UE2 above the APP meter rate
        stream_bps_ue2 = 2 * app_bps
        pg_id_ue2 = 2
        switch_ig_port = self.port3  # Trex port 2
        TREX_TX_PORT = 2
        switch_eg_port = self.port2  # Trex port 1
        TREX_RX_PORT = 1

        self.push_chassis_config()
        self.setup_queues_table()
        self.setup_slice(slice_bps)
        self.setup_acl_forwarding(in_ports=[switch_ig_port], out_port=switch_eg_port)
        # Configure common application between the two UEs
        self.setup_app_filtering(APP1_ID, slice_id=DEFAULT_SLICE_ID, l4_port=APP1_PORT)

        # UE 1 configuration
        self.setup_ue_ul(
            ue_addr=UE1_ADDR,
            ul_teid=UE1_UL_TEID,
            app_id=APP1_ID,
            app_meter_idx=UE_1_UL_APP1_METER_IDX,
            app_meter_bps=app_bps,
            sess_meter_idx=UE_1_UL_SESSION_METER_IDX,
            session_meter_bps=session_bps,
        )
        # UE 2 configuration
        self.setup_ue_ul(
            ue_addr=UE2_ADDR,
            ul_teid=UE2_UL_TEID,
            app_id=APP1_ID,
            app_meter_idx=UE_2_UL_APP_METER_IDX,
            app_meter_bps=app_bps,
            sess_meter_idx=UE_2_UL_SESSION_METER_IDX,
            session_meter_bps=session_bps,
        )

        streams = [
            self.create_gtp_stream(
                ue_addr=UE1_ADDR,
                teid=UE1_UL_TEID,
                pg_id=pg_id_ue1,
                l1_bps=stream_bps_ue1,
                dport=APP1_PORT,
            ),
            self.create_gtp_stream(
                ue_addr=UE2_ADDR,
                teid=UE2_UL_TEID,
                pg_id=pg_id_ue2,
                l1_bps=stream_bps_ue2,
                dport=APP1_PORT,
            ),
        ]
        self.trex_client.add_streams(streams, ports=TREX_TX_PORT)
        print(f"Starting traffic, duration: {TRAFFIC_DURATION_SECONDS} sec")
        self.trex_client.start(TREX_TX_PORT, duration=TRAFFIC_DURATION_SECONDS)
        live_stats = monitor_port_stats(self.trex_client)
        self.trex_client.wait_on_traffic(ports=TREX_TX_PORT, rx_delay_ms=100)
        live_stats = self.min_max_monitored_port_stats(live_stats)

        # Get and print TREX stats
        trex_stats = self.trex_client.get_stats()
        flow_stats_ue1 = get_flow_stats(pg_id_ue1, trex_stats)
        flow_stats_ue2 = get_flow_stats(pg_id_ue2, trex_stats)
        rx_bps_ue1 = (flow_stats_ue1.rx_bytes * 8) / TRAFFIC_DURATION_SECONDS
        rx_bps_ue2 = (flow_stats_ue2.rx_bytes * 8) / TRAFFIC_DURATION_SECONDS

        print("============= STATS UE 1 =============")
        print(f"    RX Rate: {to_readable(rx_bps_ue1)}")
        print(get_readable_flow_stats(flow_stats_ue1))
        print("============= STATS UE 2 =============")
        print(f"    RX Rate: {to_readable(rx_bps_ue2)}")
        print(get_readable_flow_stats(flow_stats_ue2))
        print(SEPARATOR)

        self.assertAlmostEqual(
            live_stats["min_tx"][TREX_TX_PORT] / (stream_bps_ue1 + stream_bps_ue2),
            1,
            delta=0.06,
            msg="Minimum generated traffic rate was less than expected (issue with TRex?)",
        )
        self.assertEqual(
            flow_stats_ue1.tx_packets - flow_stats_ue1.rx_packets,
            0,
            "Conforming UE shouldn't get packet drops",
        )
        # The number of dropped packets should be proportional to the excess
        # rate over the allowed app limit.
        self.assertAlmostEqual(
            (flow_stats_ue2.tx_packets - flow_stats_ue2.rx_packets)
            / flow_stats_ue2.tx_packets,
            (stream_bps_ue2 - app_bps) / stream_bps_ue2,
            delta=0.02,
            msg="Non-conforming UE experienced too much or too little drops",
        )
        self.assertAlmostEqual(
            rx_bps_ue1 / app_bps,
            1,
            delta=0.05,
            msg="UE 1 received traffic should be almost equal to the app rate",
        )
        self.assertAlmostEqual(
            rx_bps_ue2 / app_bps,
            1,
            delta=0.05,
            msg="UE 2 received traffic should be almost equal to the app rate",
        )


@group("trex-sw-mode")
@group("upf")
class UpfSessionPolicingTest(UpfPolicingTest):
    """
    Verify the behaviour of session level policing.
    Flows above the session rate should be policed, flows below the session rate shouldn't.
    """

    @autocleanup
    def runTest(self) -> None:
        session_bps = 100 * M
        slice_bps = 200 * M
        # UE1 within the session meter rate
        stream_bps_ue1 = session_bps
        pg_id_ue1 = 1
        # UE2 above the session meter rate
        stream_bps_ue2 = 2 * session_bps
        pg_id_ue2 = 2
        switch_ig_port = self.port3  # Trex port 2
        TREX_TX_PORT = 2
        switch_eg_port = self.port2  # Trex port 1
        TREX_RX_PORT = 1

        self.push_chassis_config()
        self.setup_queues_table()
        self.setup_slice(slice_bps)
        self.setup_acl_forwarding(in_ports=[switch_ig_port], out_port=switch_eg_port)

        # UE 1 configuration
        self.setup_ue_ul(
            ue_addr=UE1_ADDR,
            ul_teid=UE1_UL_TEID,
            sess_meter_idx=UE_1_UL_SESSION_METER_IDX,
            session_meter_bps=session_bps,
        )
        # UE 2 configuration
        self.setup_ue_ul(
            ue_addr=UE2_ADDR,
            ul_teid=UE2_UL_TEID,
            sess_meter_idx=UE_2_UL_SESSION_METER_IDX,
            session_meter_bps=session_bps,
        )

        streams = [
            self.create_gtp_stream(
                ue_addr=UE1_ADDR,
                teid=UE1_UL_TEID,
                pg_id=pg_id_ue1,
                l1_bps=stream_bps_ue1,
            ),
            self.create_gtp_stream(
                ue_addr=UE2_ADDR,
                teid=UE2_UL_TEID,
                pg_id=pg_id_ue2,
                l1_bps=stream_bps_ue2,
            ),
        ]
        self.trex_client.add_streams(streams, ports=TREX_TX_PORT)
        print(f"Starting traffic, duration: {TRAFFIC_DURATION_SECONDS} sec")
        self.trex_client.start(TREX_TX_PORT, duration=TRAFFIC_DURATION_SECONDS)
        live_stats = monitor_port_stats(self.trex_client)
        self.trex_client.wait_on_traffic(ports=TREX_TX_PORT, rx_delay_ms=100)
        live_stats = self.min_max_monitored_port_stats(live_stats)

        # Get and print TREX stats
        trex_stats = self.trex_client.get_stats()
        flow_stats_ue1 = get_flow_stats(pg_id_ue1, trex_stats)
        flow_stats_ue2 = get_flow_stats(pg_id_ue2, trex_stats)
        rx_bps_ue1 = (flow_stats_ue1.rx_bytes * 8) / TRAFFIC_DURATION_SECONDS
        rx_bps_ue2 = (flow_stats_ue2.rx_bytes * 8) / TRAFFIC_DURATION_SECONDS

        print("============= STATS UE 1 =============")
        print(f"    RX Rate: {to_readable(rx_bps_ue1)}")
        print(get_readable_flow_stats(flow_stats_ue1))
        print("============= STATS UE 2 =============")
        print(f"    RX Rate: {to_readable(rx_bps_ue2)}")
        print(get_readable_flow_stats(flow_stats_ue2))
        print(SEPARATOR)

        self.assertAlmostEqual(
            live_stats["min_tx"][TREX_TX_PORT] / (stream_bps_ue1 + stream_bps_ue2),
            1,
            delta=0.06,
            msg="Minimum generated traffic rate was less than expected (issue with TRex?)",
        )
        self.assertEqual(
            flow_stats_ue1.tx_packets - flow_stats_ue1.rx_packets,
            0,
            "Conforming UE shouldn't get packet drops",
        )
        # The number of dropped packets should be proportional to the excess
        # rate over the allowed session limit.
        self.assertAlmostEqual(
            (flow_stats_ue2.tx_packets - flow_stats_ue2.rx_packets)
            / flow_stats_ue2.tx_packets,
            (stream_bps_ue2 - session_bps) / stream_bps_ue2,
            delta=0.02,
            msg="Non-conforming UE experienced too much or too little drops",
        )
        self.assertAlmostEqual(
            rx_bps_ue1 / session_bps,
            1,
            delta=0.05,
            msg="UE 1 received traffic should be almost equal to the session rate",
        )
        self.assertAlmostEqual(
            rx_bps_ue2 / session_bps,
            1,
            delta=0.05,
            msg="UE 2 received traffic should be almost equal to the session rate",
        )


@group("trex-sw-mode")
@group("upf")
class UpfSliceFairPolicingTest(UpfPolicingTest):
    """
    Verifies that traffic above the session rate does not consume slice bandwidth.
    It is NOT fair for RED packets (to be dropped packets) to consume slice bandwidth.
    Session Rate = 80Mbps
    Slice Rate = 100Mbps
    Two flows for different UEs (sessions):
     1) conforming to session rate (20Mbps) (flow 1 + session rate = slice rate)
     2) misbehaving, with rate above the session rate (100Mbps)
    Output rate should be equal to the slice rate.
    Flow 1 should not be policed.
    Flow 2 should be policed to the session rate.
    Result should output rate should be slice rate.
    """

    @autocleanup
    def runTest(self) -> None:
        session_bps = 80 * M
        slice_bps = 100 * M
        # UE1 within the session meter rate
        stream_bps_ue1 = 20 * M
        pg_id_ue1 = 1
        # UE2 above the session meter rate
        stream_bps_ue2 = 100 * M
        pg_id_ue2 = 2
        switch_ig_port = self.port3  # Trex port 2
        TREX_TX_PORT = 2
        switch_eg_port = self.port2  # Trex port 1
        TREX_RX_PORT = 1

        self.push_chassis_config()
        self.setup_queues_table()
        self.setup_slice(slice_bps)
        self.setup_acl_forwarding(in_ports=[switch_ig_port], out_port=switch_eg_port)

        # UE 1 configuration
        self.setup_ue_ul(
            ue_addr=UE1_ADDR,
            ul_teid=UE1_UL_TEID,
            sess_meter_idx=UE_1_UL_SESSION_METER_IDX,
            session_meter_bps=session_bps,
        )
        # UE 2 configuration
        self.setup_ue_ul(
            ue_addr=UE2_ADDR,
            ul_teid=UE2_UL_TEID,
            sess_meter_idx=UE_2_UL_SESSION_METER_IDX,
            session_meter_bps=session_bps,
        )

        streams = [
            self.create_gtp_stream(
                ue_addr=UE1_ADDR,
                teid=UE1_UL_TEID,
                pg_id=pg_id_ue1,
                l1_bps=stream_bps_ue1,
            ),
            self.create_gtp_stream(
                ue_addr=UE2_ADDR,
                teid=UE2_UL_TEID,
                pg_id=pg_id_ue2,
                l1_bps=stream_bps_ue2,
            ),
        ]
        self.trex_client.add_streams(streams, ports=TREX_TX_PORT)
        print(f"Starting traffic, duration: {TRAFFIC_DURATION_SECONDS} sec")
        self.trex_client.start(TREX_TX_PORT, duration=TRAFFIC_DURATION_SECONDS)
        live_stats = monitor_port_stats(self.trex_client)
        self.trex_client.wait_on_traffic(ports=TREX_TX_PORT, rx_delay_ms=100)
        live_stats = self.min_max_monitored_port_stats(live_stats)

        # Get and print TREX stats
        trex_stats = self.trex_client.get_stats()
        flow_stats_ue1 = get_flow_stats(pg_id_ue1, trex_stats)
        flow_stats_ue2 = get_flow_stats(pg_id_ue2, trex_stats)
        rx_bps_ue1 = (flow_stats_ue1.rx_bytes * 8) / TRAFFIC_DURATION_SECONDS
        rx_bps_ue2 = (flow_stats_ue2.rx_bytes * 8) / TRAFFIC_DURATION_SECONDS

        print("============= STATS UE 1 =============")
        print(f"    RX Rate: {to_readable(rx_bps_ue1)}")
        print(get_readable_flow_stats(flow_stats_ue1))
        print("============= STATS UE 2 =============")
        print(f"    RX Rate: {to_readable(rx_bps_ue2)}")
        print(get_readable_flow_stats(flow_stats_ue2))
        print(SEPARATOR)

        self.assertAlmostEqual(
            live_stats["min_tx"][TREX_TX_PORT] / (stream_bps_ue1 + stream_bps_ue2),
            1,
            delta=0.06,
            msg="Minimum generated traffic rate was less than expected (issue with TRex?)",
        )
        self.assertEqual(
            flow_stats_ue1.tx_packets - flow_stats_ue1.rx_packets,
            0,
            "Conforming UE shouldn't get packet drops",
        )
        # The number of dropped packets should be proportional to the excess
        # rate over the allowed session limit.
        self.assertAlmostEqual(
            (flow_stats_ue2.tx_packets - flow_stats_ue2.rx_packets)
            / flow_stats_ue2.tx_packets,
            (stream_bps_ue2 - session_bps) / stream_bps_ue2,
            delta=0.02,
            msg="Non-conforming UE experienced too much or too little drops",
        )
        self.assertAlmostEqual(
            (rx_bps_ue1 + rx_bps_ue2) / slice_bps,
            1,
            delta=0.05,
            msg="Received traffic should be almost equal the slice rate",
        )
        self.assertAlmostEqual(
            rx_bps_ue1 / stream_bps_ue1,
            1,
            delta=0.05,
            msg="UE 1 (below session rate) received traffic should not be policed",
        )
        self.assertAlmostEqual(
            rx_bps_ue2 / session_bps,
            1,
            delta=0.05,
            msg="UE 2 (above session rate) received traffic should be policed to session rate",
        )


@group("trex-sw-mode")
@group("upf")
class UpfSessionFairPolicingTest(UpfPolicingTest):
    """
    Verifies that traffic above the app rate does not consume session bandwidth.
    It is NOT fair for RED packets (to be dropped packets) to consume session bandwidth.
    App Rate = 50Mbps
    Session Rate = 80Mbps
    Slice Rate = 200Mbps
    Two flows for different APPs:
     1) conforming to app rate (30Mbps) (flow 1 + app rate = session rate)
     2) misbehaving, with rate above the app rate and session rate (100Mbps)
    Output rate should be equal to the session rate.
    Flow 1 should be not be policed
    Flow 2 should be policed to around session rate - flow 1 rate
    Result should output rate should be the session rate.
    """

    @autocleanup
    def runTest(self) -> None:
        app_bps = 50 * M
        session_bps = 80 * M
        slice_bps = 200 * M
        # UE1 - APP1 within the session meter rate
        stream_bps_app1 = 30 * M
        pg_id_app1 = 1
        # UE1 - APP2 above the session meter rate
        stream_bps_app2 = 100 * M
        pg_id_app2 = 2
        switch_ig_port = self.port3  # Trex port 2
        TREX_TX_PORT = 2
        switch_eg_port = self.port2  # Trex port 1
        TREX_RX_PORT = 1

        self.push_chassis_config()
        self.setup_queues_table()
        self.setup_slice(slice_bps)
        self.setup_acl_forwarding(in_ports=[switch_ig_port], out_port=switch_eg_port)

        # Single session (UE) with 2 applications
        #  Setup sessions
        self.add_qer_session_meter(UE_1_UL_SESSION_METER_IDX, session_bps)
        self.setup_uplink_ue_session(
            teid=UE1_UL_TEID,
            tunnel_dst_addr=N3_ADDR,
            session_meter_idx=UE_1_UL_SESSION_METER_IDX,
        )
        #  Application 1
        self.setup_app_filtering(APP1_ID, slice_id=DEFAULT_SLICE_ID, l4_port=APP1_PORT)
        self.add_qer_app_meter(UE_1_UL_APP1_METER_IDX, app_bps)
        self.setup_uplink_termination(
            ue_session=UE1_ADDR,
            ctr_id=UPF_CTR_IDX,
            tc=DEFAULT_TC,
            app_id=APP1_ID,
            app_meter_idx=UE_1_UL_APP1_METER_IDX,
        )
        #  Application 2
        self.setup_app_filtering(APP2_ID, slice_id=DEFAULT_SLICE_ID, l4_port=APP2_PORT)
        self.add_qer_app_meter(UE_1_UL_APP2_METER_IDX, app_bps)
        self.setup_uplink_termination(
            ue_session=UE1_ADDR,
            ctr_id=UPF_CTR_IDX,
            tc=DEFAULT_TC,
            app_id=APP2_ID,
            app_meter_idx=UE_1_UL_APP2_METER_IDX,
        )

        streams = [
            self.create_gtp_stream(
                ue_addr=UE1_ADDR,
                teid=UE1_UL_TEID,
                pg_id=pg_id_app1,
                l1_bps=stream_bps_app1,
                dport=APP1_PORT,
            ),
            self.create_gtp_stream(
                ue_addr=UE1_ADDR,
                teid=UE1_UL_TEID,
                pg_id=pg_id_app2,
                l1_bps=stream_bps_app2,
                dport=APP2_PORT,
            ),
        ]
        self.trex_client.add_streams(streams, ports=TREX_TX_PORT)
        print(f"Starting traffic, duration: {TRAFFIC_DURATION_SECONDS} sec")
        self.trex_client.start(TREX_TX_PORT, duration=TRAFFIC_DURATION_SECONDS)
        live_stats = monitor_port_stats(self.trex_client)
        self.trex_client.wait_on_traffic(ports=TREX_TX_PORT, rx_delay_ms=100)
        live_stats = self.min_max_monitored_port_stats(live_stats)

        # Get and print TREX stats
        trex_stats = self.trex_client.get_stats()
        flow_stats_app1 = get_flow_stats(pg_id_app1, trex_stats)
        flow_stats_app2 = get_flow_stats(pg_id_app2, trex_stats)
        rx_bps_app1 = (flow_stats_app1.rx_bytes * 8) / TRAFFIC_DURATION_SECONDS
        rx_bps_app2 = (flow_stats_app2.rx_bytes * 8) / TRAFFIC_DURATION_SECONDS

        print("============= STATS APP 1 =============")
        print(f"    RX Rate: {to_readable(rx_bps_app1)}")
        print(get_readable_flow_stats(flow_stats_app1))
        print("============= STATS APP 2 =============")
        print(f"    RX Rate: {to_readable(rx_bps_app2)}")
        print(get_readable_flow_stats(flow_stats_app2))
        print(SEPARATOR)

        self.assertAlmostEqual(
            live_stats["min_tx"][TREX_TX_PORT] / (stream_bps_app1 + stream_bps_app2),
            1,
            delta=0.06,
            msg="Minimum generated traffic rate was less than expected (issue with TRex?)",
        )
        self.assertEqual(
            flow_stats_app1.tx_packets - flow_stats_app1.rx_packets,
            0,
            "Conforming UE shouldn't get packet drops",
        )
        # The number of dropped packets should be proportional to the excess
        # rate over the allowed app limit.
        self.assertAlmostEqual(
            (flow_stats_app2.tx_packets - flow_stats_app2.rx_packets)
            / flow_stats_app2.tx_packets,
            (stream_bps_app2 - app_bps) / stream_bps_app2,
            delta=0.02,
            msg="Non-conforming UE experienced too much or too little drops",
        )
        self.assertAlmostEqual(
            (rx_bps_app1 + rx_bps_app2) / session_bps,
            1,
            delta=0.05,
            msg="Received traffic should be almost equal to the session rate",
        )
        self.assertAlmostEqual(
            rx_bps_app1 / stream_bps_app1,
            1,
            delta=0.05,
            msg="App 1 (below app rate) received traffic should not be policed",
        )
        self.assertAlmostEqual(
            rx_bps_app2 / app_bps,
            1,
            delta=0.05,
            msg="App 2 (above app rate) received traffic should be policed to app rate",
        )
