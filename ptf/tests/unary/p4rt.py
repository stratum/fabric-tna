# Copyright 2013-2018 Barefoot Networks, Inc.
# Copyright 2018-present Open Networking Foundation
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0 AND Apache-2.0

from fabric_test import *  # noqa
from ptf.testutils import group
from base_test import autocleanup, tvsetup

@group("p4rt")
class TableEntryReadWriteTest(FabricTest):
    @tvsetup
    @autocleanup
    def doRunTest(self):
        req, _ = self.add_bridging_entry(1, "00:00:00:00:00:01", "ff:ff:ff:ff:ff:ff", 1)
        expected_bridging_entry = req.updates[0].entity.table_entry
        received_bridging_entry = self.read_bridging_entry(
            1, "00:00:00:00:00:01", "ff:ff:ff:ff:ff:ff"
        )
        self.verify_p4runtime_entity(expected_bridging_entry, received_bridging_entry)

        req, _ = self.add_forwarding_acl_punt_to_cpu(ETH_TYPE_IPV4)
        expected_acl_entry = req.updates[0].entity.table_entry
        received_acl_entry = self.read_forwarding_acl_punt_to_cpu(ETH_TYPE_IPV4)
        self.verify_p4runtime_entity(expected_acl_entry, received_acl_entry)

        req, _ = self.add_forwarding_acl_set_output_port(self.port2, ig_port=self.port1)
        expected_acl_entry = req.updates[0].entity.table_entry
        received_acl_entry = self.read_forwarding_acl_set_output_port(ig_port=self.port1)
        self.verify_p4runtime_entity(expected_acl_entry, received_acl_entry)

    def runTest(self):
        print("")
        self.doRunTest()


@group("p4rt")
class ActionProfileMemberReadWriteTest(FabricTest):
    @tvsetup
    @autocleanup
    def doRunTest(self):
        req, _ = self.add_next_hashed_group_member(
            "output_hashed", [("port_num", stringify(self.port1, 4))]
        )
        expected_action_profile_member = req.updates[0].entity.action_profile_member
        mbr_id = expected_action_profile_member.member_id
        received_action_profile_member = self.read_next_hashed_group_member(mbr_id)
        self.verify_p4runtime_entity(
            expected_action_profile_member, received_action_profile_member
        )

    def runTest(self):
        print("")
        self.doRunTest()


@group("p4rt")
class ActionProfileGroupReadWriteTest(FabricTest):
    @tvsetup
    @autocleanup
    def doRunTest(self):
        req, _ = self.add_next_hashed_group_member(
            "output_hashed", [("port_num", stringify(1, 4))]
        )
        member_installed = req.updates[0].entity.action_profile_member
        mbr_id = member_installed.member_id

        grp_id = 1
        req, _ = self.add_next_hashed_group(grp_id, [mbr_id])
        expected_action_profile_group = req.updates[0].entity.action_profile_group
        self.verify_next_hashed_group(grp_id, expected_action_profile_group)

    def runTest(self):
        print("")
        self.doRunTest()


@group("p4rt")
class ActionProfileGroupModificationTest(FabricTest):
    @tvsetup
    @autocleanup
    def doRunTest(self):
        # Insert members
        mbr_ids = []
        for port_num in range(1, 4):
            req, _ = self.add_next_hashed_group_member(
                "output_hashed", [("port_num", stringify(port_num, 4))]
            )
            member_installed = req.updates[0].entity.action_profile_member
            mbr_ids.append(member_installed.member_id)

        # Insert group with member-1 and member-2
        grp_id = 1
        req, _ = self.add_next_hashed_group(grp_id, mbr_ids[:2])
        expected_action_profile_group = req.updates[0].entity.action_profile_group
        received_action_profile_group = self.read_next_hashed_group(grp_id)
        self.verify_p4runtime_entity(
            expected_action_profile_group, received_action_profile_group
        )

        # Modify group with member-2 and member-3
        req, _ = self.modify_next_hashed_group(grp_id, mbr_ids[1:], grp_size=2)
        expected_action_profile_group = req.updates[0].entity.action_profile_group
        received_action_profile_group = self.read_next_hashed_group(grp_id)
        self.verify_p4runtime_entity(
            expected_action_profile_group, received_action_profile_group
        )

    def runTest(self):
        print("")
        self.doRunTest()


@group("p4rt")
class MulticastGroupReadWriteTest(FabricTest):
    @tvsetup
    @autocleanup
    def doRunTest(self):
        grp_id = 10
        # (instance, port)
        replicas = [(0, self.port1), (0, self.port2), (0, self.port3)]
        req, _ = self.add_mcast_group(grp_id, replicas)
        expected_mc_entry = req.updates[
            0
        ].entity.packet_replication_engine_entry.multicast_group_entry
        self.verify_mcast_group(grp_id, expected_mc_entry)

    def runTest(self):
        print("")
        self.doRunTest()


@group("p4rt")
class MulticastGroupModificationTest(FabricTest):

    # Not using the auto cleanup since the Stratum modifies the
    # multicast node table internally
    @tvsetup
    def doRunTest(self):
        # Add group with egress port 1~3 (instance 1 and 2)
        grp_id = 10
        # (instance, port)
        replicas = [
          (1, self.port1),
          (1, self.port2),
          (1, self.port3),
          (2, self.port1),
          (2, self.port2),
          (2, self.port3),
        ]
        self.add_mcast_group(grp_id, replicas)

        # Modify the group with egress port 2~4 (instance 2 and 3)
        # (instance, port)
        replicas = [(2, 2), (2, 3), (2, 4), (3, 2), (3, 3), (3, 4)]
        req, _ = self.modify_mcast_group(grp_id, replicas)
        expected_mc_entry = req.updates[
            0
        ].entity.packet_replication_engine_entry.multicast_group_entry
        self.verify_mcast_group(grp_id, expected_mc_entry)

        # Cleanup
        self.delete_mcast_group(grp_id)

    def runTest(self):
        print("")
        self.doRunTest()


@group("p4rt")
class CounterTest(BridgingTest):
    @tvsetup
    @autocleanup
    def doRunTest(self):
        pkt = getattr(testutils, "simple_tcp_packet")(pktlen=120)
        self.runBridgingTest(False, False, pkt)
        # Check direct counters from 'ingress_port_vlan' table
        table_entries = [
            req.updates[0].entity.table_entry
            for req in self.reqs
            if req.updates[0].entity.HasField("table_entry")
        ]
        ingress_port_vlan_tid = self.get_table_id("ingress_port_vlan")
        table_entries = [
            te for te in table_entries if te.table_id == ingress_port_vlan_tid
        ]

        # Here, both table entries hits once with a
        # simple TCP packet(120 bytes + 2*2 bytes checksum inserted by scapy)
        for table_entry in table_entries:
            self.verify_direct_counter(table_entry, 124, 1)

        # Check that direct counters can be set/cleared.
        for table_entry in table_entries:
            self.write_direct_counter(table_entry, 0, 0)
            self.verify_direct_counter(table_entry, 0, 0)

            self.write_direct_counter(table_entry, 1024, 1024)
            self.verify_direct_counter(table_entry, 1024, 1024)

        try:
            self.get_counter("fwd_type_counter")
        except Exception:
            print("Unable to find indirect counter `fwd_type_counter`, skip")
            return

        # Read indirect counter (fwd_type_counter)
        # Here we are trying to read counter for traffic class "0"
        # which means how many traffic for bridging
        # In the bridging test we sent two TCP packets and both packets
        # are classified as bridging class.
        self.verify_indirect_counter("fwd_type_counter", 0, "BOTH", 248, 2)

    def runTest(self):
        print("")
        self.doRunTest()
