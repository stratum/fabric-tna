#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2020 Open Networking Foundation <info@opennetworking.org>
# SPDX-License-Identifier: LicenseRef-ONF-Member-1.0
import sys

sys.path.append('/p4runtime-sh/')

import p4runtime_sh.shell as sh
import struct
import argparse
from ipaddress import IPv4Network, IPv4Address

FALSE = '0'
TRUE = '1'
DIR_UPLINK = '1'
DIR_DOWNLINK = '2'
IFACE_ACCESS = '1'
IFACE_CORE = '2'
TUNNEL_SPORT = '2152'
TUNNEL_TYPE_GPDU = '3'


def get_args():
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
#    parser.add_argument(
#        "--add-ifaces", action='store_true',
#        help="If this argument is present, interface table entries will be installed.")
#    parser.add_argument(
#        "--buffer", action='store_true',
#        help="If this argument is present, downlink fars will have" +
#        " the buffering flag set to true")
#    parser.add_argument("--ue-count", type=int, default=1,
#                        help="The number of UE flows for which table entries should be created.")
#    parser.add_argument("--ue-pool", type=IPv4Network, default=IPv4Network("17.0.0.0/24"),
#                        help="The IPv4 prefix from which UE addresses will be drawn.")
#    parser.add_argument("--s1u-addr", type=IPv4Address, default=IPv4Address("140.0.100.254"),
#                        help="The IPv4 address of the UPF's S1U interface")
#    parser.add_argument("--enb-addr", type=IPv4Address, default=IPv4Address("140.0.100.1"),
#                        help="The IPv4 address of the eNodeB")
#    parser.add_argument(
#        "--teid-base", type=int, default=255, help="The first TEID to use for the first UE. " +
#        "Further TEIDs will be generated by incrementing.")
#    parser.add_argument("--session-id", type=int, default=1,
#                        help="The ID of the PFCP session that is creating these PDRs and FARs")
#    parser.add_argument(
#        "--pdr-base", type=int, default=1, help="The first PDR ID to use for the first UE. " +
#        "Further PDR IDs will be generated by incrementing.")
#    parser.add_argument(
#        "--far-base", type=int, default=1, help="The first FAR ID to use for the first UE. " +
#        "Further FAR IDs will be generated by incrementing.")
#    parser.add_argument(
#        "--ctr-base", type=int, default=1,
#        help="The first PDR counter index to use for the first UE. " +
#        "Further counter indices will be generated by incrementing.")
#    parser.add_argument("--server", type=str, default="onos1:51001",
    parser.add_argument("--server", type=str, default="10.64.12.131:9339",
                        help="Address and port of the p4runtime server.")
#    parser.add_argument("action", choices=["program", "clear", "dry"])
    return parser.parse_args()


args = get_args()


def get_addresses_from_prefix(prefix: IPv4Network, count: int):
    # Currently this doesn't allow the address with host bits all 0,
    #  so the first host address is (prefix_addr & mask) + 1
    if count >= 2**(prefix.max_prefixlen - prefix.prefixlen):
        raise Exception("trying to generate more addresses than a prefix contains!")
    base_addr = ip2int(prefix.network_address) + 1
    offset = 0
    while offset < count:
        yield IPv4Address(base_addr + offset)
        offset += 1


def ip2int(addr: IPv4Address):
    return struct.unpack("!I", addr.packed)[0]


def int2ip(addr: int):
    return IPv4Address(addr)


entries = []


def add_entry(entry, action):
    if action == "program":
        try:
            entry.insert()
            print("*** Entry added.")
        except Exception as e:
            print("Except during table insertion:", e)
            print("Entry was:", entry)
            print("%d entries were successfully added before failure" % len(entries))
            clear_entries()
            sys.exit(1)
    entries.append(entry)


def clear_entries():
    for i, entry in enumerate(entries):
        entry.delete()
        print("*** Entry %d of %d deleted." % (i + 1, len(entries)))


def main():
    # Connect to gRPC server
    sh.setup(
        device_id=1,
        grpc_addr=args.server,
        election_id=(1, 0),  # (high, low)
        config=sh.FwdPipeConfig('/scripts/p4info_fabric-spq-conquest_v9.3.1.txt', '/scripts/pipeline_config.pb_fabric-spq-conquest_v9.3.1.bin'))

    # acl
    te = sh.TableEntry('FabricIngress.acl.acl')(action='FabricIngress.acl.set_output_port')
    te.match['ig_port'] = '48'
    te.priority = 10
    te.action['port_num'] = '56'
#    te.counter_data
#    te.insert()
#    te.read(lambda e: print(e))
    add_entry(te, 'program')

    te = sh.TableEntry('FabricIngress.acl.acl')(action='FabricIngress.acl.set_output_port')
    te.match['ig_port'] =  '56'
    te.priority = 10
    te.action['port_num'] = '48'
    add_entry(te, 'program')
#    te.counter_data
#    te.insert()
#    te.read(lambda e: print(e))

    # pop vlan
    pop = sh.TableEntry('FabricEgress.egress_next.egress_vlan')(action='FabricEgress.egress_next.pop_vlan')
    pop.match['vlan_id'] = '0xFFE'
    pop.match['eg_port'] = '56'
#    pop.insert()
    add_entry(pop, 'program')

    pop = sh.TableEntry('FabricEgress.egress_next.egress_vlan')(action='FabricEgress.egress_next.pop_vlan')
    pop.match['vlan_id'] = '0xFFE'
    pop.match['eg_port'] = '48'
#    pop.insert()
    add_entry(pop, 'program')

    # ConQuest
    con = sh.TableEntry('FabricEgress.conquest_egress.tb_per_flow_action')(action='FabricEgress.conquest_egress.trigger_report')
#    con.match['snap_0'] = '0..131071'
#    con.match['q_delay'] = '0..262143'
#    con.match['random_bits'] = '0..255'
    con.match['ecn'] = '1'
    con.priority = 10
    add_entry(con, 'program')
#    con.read(lambda e: print(e))
#    con.insert()
    
    # Mirror
    CONQ_REPORT_MIRROR_IDS = [400, 401, 402, 403]
    for sid in CONQ_REPORT_MIRROR_IDS:
        c = clone_session_entry(session_id=sid)
        c.cos = 0
        c.replicas = [Replica(32, 0)]
        add_entry(c, 'program')
#        c.insert()
#        clone_session_entry(session_id=0).read(lambda e: print(e))

    # packetio
    te = sh.TableEntry('switch_info')(action='set_switch_info')
    te.action['cpu_port'] = '320'  # 192 for 2 pipe
    te.is_default = True
    te.modify()

    # ========================#
    # Interface Entries
    #  Filter entries are now installed when the netconfig is loaded,
    #  and do not need to be installed via P4RT.
    # ========================#
#    if args.add_ifaces:
#        # Uplink
#        entry = sh.TableEntry('PreQosPipe.source_iface_lookup')(
#            action='PreQosPipe.set_source_iface')
#        entry.match['ipv4_dst_prefix'] = str(args.s1u_addr) + '/32'
#        entry.action['src_iface'] = IFACE_ACCESS
#        entry.action['direction'] = DIR_UPLINK
#        add_entry(entry, args.action)
#
#        # Downlink
#        entry = sh.TableEntry('PreQosPipe.source_iface_lookup')(
#            action='PreQosPipe.set_source_iface')
#        entry.match['ipv4_dst_prefix'] = str(args.ue_pool)
#        entry.action['src_iface'] = IFACE_CORE
#        entry.action['direction'] = DIR_DOWNLINK
#        add_entry(entry, args.action)
#
#    # table entry parameter generators
#    rule_count = args.ue_count * 2
#    ue_addr_gen = get_addresses_from_prefix(args.ue_pool, args.ue_count)
#    teid_gen = iter(range(args.teid_base, args.teid_base + args.ue_count))
#    far_id_gen = iter(range(args.far_base, args.far_base + rule_count))
#    pdr_id_gen = iter(range(args.pdr_base, args.pdr_base + rule_count))
#    ctr_id_gen = iter(range(args.ctr_base, args.ctr_base + rule_count))
#
#    for ue_index in range(args.ue_count):
#        ue_addr = next(ue_addr_gen)
#        teid = next(teid_gen)
#
#        pdr_uplink = next(pdr_id_gen)
#        pdr_downlink = next(pdr_id_gen)
#
#        far_uplink = next(far_id_gen)
#        far_downlink = next(far_id_gen)
#
#        pdr_ctr_uplink = next(ctr_id_gen)
#        pdr_ctr_downlink = next(ctr_id_gen)
#
#        # ========================#
#        # PDR Entries
#        # ========================#
#
#        ## Uplink
#        entry = sh.TableEntry('PreQosPipe.pdrs')(action='PreQosPipe.set_pdr_attributes')
#        # Match fields
#        entry.match['src_iface'] = IFACE_ACCESS
#        entry.match['ue_addr'] = str(ue_addr)
#        entry.match['teid'] = str(teid)
#        entry.match['tunnel_ipv4_dst'] = str(args.s1u_addr)
#        # Action params
#        entry.action['id'] = str(pdr_uplink)
#        entry.action['fseid'] = str(args.session_id)
#        entry.action['ctr_id'] = str(pdr_ctr_uplink)
#        entry.action['far_id'] = str(far_uplink)
#        add_entry(entry, args.action)
#
#        ## Downlink
#        entry = sh.TableEntry('PreQosPipe.pdrs')(action='PreQosPipe.set_pdr_attributes')
#        # Match fields
#        entry.match['src_iface'] = IFACE_CORE
#        entry.match['ue_addr'] = str(ue_addr)
#        # Action params
#        entry.action['id'] = str(pdr_downlink)
#        entry.action['fseid'] = str(args.session_id)
#        entry.action['ctr_id'] = str(pdr_ctr_downlink)
#        entry.action['far_id'] = str(far_downlink)
#        add_entry(entry, args.action)
#
#        # ========================#
#        # FAR Entries
#        # ========================#
#
#        ## Uplink
#        entry = sh.TableEntry('PreQosPipe.load_far_attributes')(
#            action='PreQosPipe.load_normal_far_attributes')
#        # Match fields
#        entry.match['far_id'] = str(far_uplink)
#        entry.match['session_id'] = str(args.session_id)
#        # Action params
#        entry.action['needs_dropping'] = FALSE
#        entry.action['notify_cp'] = FALSE
#        add_entry(entry, args.action)
#
#        ## Downlink
#        entry = sh.TableEntry('PreQosPipe.load_far_attributes')(
#            action='PreQosPipe.load_tunnel_far_attributes')
#        # Match fields
#        entry.match['far_id'] = str(far_downlink)
#        entry.match['session_id'] = str(args.session_id)
#        # Action params
#        entry.action['needs_dropping'] = FALSE
#        entry.action['notify_cp'] = FALSE
#        entry.action['needs_buffering'] = TRUE if args.buffer else FALSE
#        entry.action['tunnel_type'] = TUNNEL_TYPE_GPDU
#        entry.action['src_addr'] = str(args.s1u_addr)
#        entry.action['dst_addr'] = str(args.enb_addr)
#        entry.action['teid'] = str(teid)
#        entry.action['sport'] = TUNNEL_SPORT
#        add_entry(entry, args.action)
#
#    if args.action == "program":
#        print("All entries added sucessfully.")
#
#    elif args.action == "clear":
#        clear_entries()
#
#    elif args.action == "dry":
#        for entry in entries:
#            print(entry)
#
    sh.teardown()


if __name__ == "__main__":
    main()
