# Copyright 2021-present Open Networking Foundation
# SPDX-License-Identifier: Apache-2.0


from base_test import autocleanup, is_v1model, stringify, tvsetup
from fabric_test import *  # noqa
from p4.v1 import p4runtime_pb2
from scapy.contrib.gtp import GTP_U_Header
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.sctp import SCTP


class StatsIPv4UnicastTest(StatsTest, IPv4UnicastTest):
    """Wraps IPv4UnicastTest"""

    def runStatsIPv4UnicastTest(self, stats_flow_id, **kwargs):
        pkt = kwargs["pkt"].copy()
        if GTP_U_Header in pkt:
            inner_most_pkt = pkt_remove_gtp(pkt)
        else:
            inner_most_pkt = pkt
        ftuple = {
            "ipv4_src": inner_most_pkt[IP].src,
            "ipv4_dst": inner_most_pkt[IP].dst,
            "ip_proto": inner_most_pkt[IP].proto,
        }
        if UDP in inner_most_pkt:
            ftuple["l4_sport"] = inner_most_pkt[UDP].sport
            ftuple["l4_dport"] = inner_most_pkt[UDP].dport
        elif TCP in inner_most_pkt:
            ftuple["l4_sport"] = inner_most_pkt[TCP].sport
            ftuple["l4_dport"] = inner_most_pkt[TCP].dport
        elif SCTP in inner_most_pkt:
            ftuple["l4_sport"] = None
            ftuple["l4_dport"] = None
        elif ICMP in inner_most_pkt:
            ftuple["l4_sport"] = None
            ftuple["l4_dport"] = None
        else:
            self.fail("Unsupported protocol")

        self.set_up_stats_flows(
            stats_flow_id=stats_flow_id,
            ig_port=self.port1,
            eg_port=self.port2,
            **ftuple
        )
        self.runIPv4UnicastTest(**kwargs)
        if is_v1model():
            # target bmv2 does not count FCS bytes because it uses software interfaces ('veth').
            expected_ingress_bytes = len(pkt)
        else:
            expected_ingress_bytes = len(pkt) + ETH_FCS_BYTES
        if kwargs["tagged1"]:
            expected_ingress_bytes += VLAN_BYTES
        if self.loopback:
            expected_ingress_bytes += CPU_LOOPBACK_FAKE_ETH_BYTES
        if is_v1model():
            expected_egress_bytes = expected_ingress_bytes
        else:
            expected_egress_bytes = expected_ingress_bytes + BMD_BYTES

        self.verify_stats_counter(
            gress=STATS_INGRESS,
            stats_flow_id=stats_flow_id,
            port=self.port1,
            byte_count=expected_ingress_bytes,
            pkt_count=1,
            **ftuple
        )
        self.verify_stats_counter(
            gress=STATS_EGRESS,
            stats_flow_id=stats_flow_id,
            port=self.port2,
            byte_count=expected_egress_bytes,
            pkt_count=1,
            **ftuple
        )


class FabricStatsIPv4UnicastTest(StatsIPv4UnicastTest):
    """Tests stats counters for IPv4 unicast routing with different packet types"""

    @tvsetup
    @autocleanup
    def doRunTest(self, pkt, stats_flow_id, mac_dest, tagged1, tagged2, tc_name):
        self.runStatsIPv4UnicastTest(
            pkt=pkt,
            stats_flow_id=stats_flow_id,
            next_hop_mac=mac_dest,
            tagged1=tagged1,
            tagged2=tagged2,
        )

    def runTest(self):
        print("")
        # Arbitrary stat flow id. Zero is a reserved value
        stats_flow_id = 1
        for vlan_conf, tagged in vlan_confs.items():
            for pkt_type in BASE_PKT_TYPES | GTP_PKT_TYPES:
                tc_name = pkt_type + "_VLAN_" + vlan_conf
                print("Testing {} packet with VLAN {}...".format(pkt_type, vlan_conf))
                pkt = getattr(testutils, "simple_%s_packet" % pkt_type)(
                    eth_src=HOST1_MAC,
                    eth_dst=SWITCH_MAC,
                    ip_src=HOST1_IPV4,
                    ip_dst=HOST2_IPV4,
                    pktlen=MIN_PKT_LEN,
                )
                self.doRunTest(
                    pkt=pkt,
                    stats_flow_id=stats_flow_id,
                    mac_dest=HOST2_MAC,
                    tagged1=tagged[0],
                    tagged2=tagged[1],
                    tc_name=tc_name,
                )
                stats_flow_id += 1
