# Copyright 2021-present Open Networking Foundation
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0 AND Apache-2.0

from base_test import autocleanup, stringify, tvsetup
from fabric_test import *  # noqa
from p4.v1 import p4runtime_pb2
from scapy.contrib.gtp import GTP_U_Header
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.sctp import SCTP

INGRESS = "Ingress"
EGRESS = "Egress"

STATS_TABLE = "Fabric%s.stats.flows"
STATS_ACTION = "Fabric%s.stats.count"


class StatsTest(FabricTest):
    """Mixin class with methods to manipulate stats tables and to verify
    counters.

    Most methods take a generic dictionary 'ftuple', expected to contain
    values for the 5-tuple to match: ipv4_src, ipv4_dst, ip_proto, l4_sport, and
    l4_dport.
    """

    def build_stats_matches(self, gress, stats_flow_id, port, **ftuple):
        port_ = stringify(port, 2)
        stats_flow_id_ = stringify(stats_flow_id, 2)
        if gress == INGRESS:
            matches = self.build_acl_matches(**ftuple)
            matches.append(self.Exact("ig_port", port_))
        else:
            matches = []
            matches.append(self.Exact("stats_flow_id", stats_flow_id_))
            matches.append(self.Exact("eg_port", port_))
        return matches

    def build_stats_table_entry(self, gress, stats_flow_id, port, **ftuple):
        table_entry = p4runtime_pb2.TableEntry()
        table_name = STATS_TABLE % gress
        table_entry.table_id = self.get_table_id(table_name)
        table_entry.priority = DEFAULT_PRIORITY if gress == INGRESS else 0
        matches = self.build_stats_matches(
            gress=gress, stats_flow_id=stats_flow_id, port=port, **ftuple
        )
        self.set_match_key(table_entry, table_name, matches)
        return table_entry

    def reset_stats_counter(self, table_entry):
        self.write_direct_counter(table_entry, 0, 0)

    def verify_stats_counter(
        self, gress, stats_flow_id, port, byte_count, pkt_count, **ftuple
    ):
        # ONOS will read stats counters during flow rule reconciliation. Here we
        # do the same by reading a TableEntry and extracting counter_data
        # (instead of reading DirectCounterEntry).
        req = self.get_new_read_request()
        entity = req.entities.add()
        entity.table_entry.CopyFrom(
            self.build_stats_table_entry(
                gress=gress, stats_flow_id=stats_flow_id, port=port, **ftuple
            )
        )
        entity.table_entry.counter_data.CopyFrom(p4runtime_pb2.CounterData())
        entities = self.read_request(req)
        if self.generate_tv:
            # TODO
            return
        if len(entities) != 1:
            self.fail("Expected 1 table entry got %d" % len(entities))
        entity = entities.pop()
        if not entity.HasField("table_entry"):
            self.fail("Expected table entry got something else")
        counter_data = entity.table_entry.counter_data
        if (
            counter_data.byte_count != byte_count
            or counter_data.packet_count != pkt_count
        ):
            self.fail(
                "Counter is not same as expected.\
                \nActual packet count: %d, Expected packet count: %d\
                \nActual byte count: %d, Expected byte count: %d\n"
                % (
                    counter_data.packet_count,
                    pkt_count,
                    counter_data.byte_count,
                    byte_count,
                )
            )

    def add_stats_table_entry(self, gress, stats_flow_id, ports, **ftuple):
        for port in ports:
            matches = self.build_stats_matches(
                gress=gress, stats_flow_id=stats_flow_id, port=port, **ftuple
            )
            if gress == INGRESS:
                action_param = [("flow_id", stringify(stats_flow_id, 2))]
            else:
                action_param = []
            self.send_request_add_entry_to_action(
                STATS_TABLE % gress,
                matches,
                STATS_ACTION % gress,
                action_param,
                DEFAULT_PRIORITY if gress == INGRESS else 0,
            )

    def set_up_stats_flows(self, stats_flow_id, ig_port, eg_port, **ftuple):
        self.add_stats_table_entry(
            gress=INGRESS, stats_flow_id=stats_flow_id, ports=[ig_port], **ftuple
        )
        self.add_stats_table_entry(
            gress=EGRESS, stats_flow_id=stats_flow_id, ports=[eg_port], **ftuple
        )
        # FIXME: check P4RT spec, are counters reset upon table insert?
        self.reset_stats_counter(
            self.build_stats_table_entry(
                gress=INGRESS, stats_flow_id=stats_flow_id, port=ig_port, **ftuple
            )
        )
        self.reset_stats_counter(
            self.build_stats_table_entry(
                gress=EGRESS, stats_flow_id=stats_flow_id, port=eg_port, **ftuple
            )
        )


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
        expected_ingress_bytes = len(pkt) + ETH_FCS_BYTES
        if kwargs["tagged1"]:
            expected_ingress_bytes += VLAN_BYTES
        if self.loopback:
            expected_ingress_bytes += CPU_LOOPBACK_FAKE_ETH_BYTES
        expected_egress_bytes = expected_ingress_bytes + BMD_BYTES

        self.verify_stats_counter(
            gress=INGRESS,
            stats_flow_id=stats_flow_id,
            port=self.port1,
            byte_count=expected_ingress_bytes,
            pkt_count=1,
            **ftuple
        )
        self.verify_stats_counter(
            gress=EGRESS,
            stats_flow_id=stats_flow_id,
            port=self.port2,
            byte_count=expected_egress_bytes,
            pkt_count=1,
            **ftuple
        )


class FabricStatsIPv4UnicastTest(StatsIPv4UnicastTest):
    """Tests stats counters for IPv4 unicast routing with different packet types
    """

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
