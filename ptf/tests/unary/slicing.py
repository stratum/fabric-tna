# Copyright 2021-present Open Networking Foundation
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0 AND Apache-2.0

from scapy.layers.inet import IP

from base_test import autocleanup, tvsetup
from fabric_test import *  # noqa

COLOR_GREEN = 0
COLOR_YELLOW = 1
COLOR_RED = 3


class SlicingTest(FabricTest):
    """Mixin class with methods to manipulate QoS entities
    """

    def slice_tc_index(self, slice_id, tc):
        return (slice_id << 4) + tc

    def add_slice_tc_classifier_entry(self, slice_id, tc, **ftuple):
        self.send_request_add_entry_to_action(
            "FabricIngress.slice_tc_classifier.classifier",
            self.build_acl_matches(**ftuple),
            "FabricIngress.slice_tc_classifier.set_slice_id_tc",
            [
                ("slice_id", stringify(slice_id, 1)),
                ("tc", stringify(tc, 1))
            ],
            DEFAULT_PRIORITY,
        )

    def configure_slice_tc_meter(self, slice_id, tc, cir, cburst, pir, pburst):
        self.write_indirect_meter(
            m_name="FabricIngress.qos.slice_tc_meter",
            m_index=self.slice_tc_index(slice_id, tc),
            cir=cir,
            cburst=cburst,
            pir=pir,
            pburst=pburst
        )

    def add_queue_entry(self, slice_id, tc, qid=None, color=None):
        matches = [
            self.Exact("slice_id", stringify(slice_id, 1)),
            self.Exact("tc", stringify(tc, 1))
        ]
        if color is not None:
            matches.append(self.Ternary("color", stringify(color, 1), stringify(0x3, 1)))
        if qid is not None:
            action = "FabricIngress.qos.set_queue"
            action_params = [("qid", stringify(qid, 1))]
        else:
            action = "FabricIngress.qos.meter_drop"
            action_params = []
        self.send_request_add_entry_to_action(
            "FabricIngress.qos.queues",
            matches,
            action,
            action_params,
            DEFAULT_PRIORITY,
        )

    def enable_policing(self, slice_id, tc, color=COLOR_RED):
        self.add_queue_entry(slice_id, tc, None, color=color)


class IPv4UnicastWithPolicingTest(SlicingTest, IPv4UnicastTest):
    """Tests QoS policer. This is mostly a dummmy test class to verify basic programming of
    QoS-related entities. Most of the QoS tests should use linerate traffic generation. """

    @tvsetup
    @autocleanup
    def doRunTest(self, pkt, policing, tc_name, **kwargs):
        slice_id = 1
        tc = 1
        self.add_slice_tc_classifier_entry(
            slice_id=slice_id,
            tc=tc,
            ipv4_src=pkt[IP].src
        )
        # 1 byte burst, any packet should be RED
        self.configure_slice_tc_meter(
            slice_id=slice_id, tc=tc, cir=1, cburst=1, pir=1, pburst=1
        )
        if policing:
            self.enable_policing(slice_id=slice_id, tc=tc, color=COLOR_RED)
        else:
            self.add_queue_entry(slice_id=slice_id, tc=tc, qid=1)
        self.runIPv4UnicastTest(pkt, verify_pkt=(not policing), **kwargs)
        if policing:
            self.verify_no_other_packets()

    def runTest(self):
        print("")
        for pkt_type in BASE_PKT_TYPES:
            for policing in [True, False]:
                tc_name = f"{pkt_type}_{'with' if policing else 'without'}_policing"
                print("Testing {} packet, policing={}...".format(pkt_type, policing))
                pkt = getattr(testutils, "simple_%s_packet" % pkt_type)(
                    eth_src=HOST1_MAC,
                    eth_dst=SWITCH_MAC,
                    ip_src=HOST1_IPV4,
                    ip_dst=HOST2_IPV4,
                    pktlen=MIN_PKT_LEN,
                )
                self.doRunTest(
                    pkt=pkt,
                    policing=policing,
                    next_hop_mac=HOST2_MAC,
                    tc_name=tc_name,
                )
