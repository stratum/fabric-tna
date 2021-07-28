# Copyright 2013-2018 Barefoot Networks, Inc.
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0 AND Apache-2.0

# eXtensible Network Telemetry

import logging
import os
from os.path import abspath, exists, splitext

import matplotlib.pyplot as plt
import numpy as np
from scapy.fields import BitField, ShortField, XByteField, XIntField, XShortField
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Packet, bind_layers
from scapy.utils import PcapReader, inet_aton
from scipy import stats


class INT_META_HDR(Packet):
    name = "INT_META"
    fields_desc = [
        BitField("ver", 0, 4),
        BitField("rep", 0, 2),
        BitField("c", 0, 1),
        BitField("e", 0, 1),
        BitField("rsvd1", 0, 3),
        BitField("ins_cnt", 0, 5),
        BitField("max_hop_cnt", 32, 8),
        BitField("total_hop_cnt", 0, 8),
        ShortField("inst_mask", 0),
        ShortField("rsvd2", 0x0000),
    ]


class INT_L45_HEAD(Packet):
    name = "INT_L45_HEAD"
    fields_desc = [
        XByteField("int_type", 0x01),
        XByteField("rsvd0", 0x00),
        XByteField("length", 0x00),
        XByteField("rsvd1", 0x00),
    ]


class INT_L45_TAIL(Packet):
    name = "INT_L45_TAIL"
    fields_desc = [
        XByteField("next_proto", 0x01),
        XShortField("proto_param", 0x0000),
        XByteField("rsvd", 0x00),
    ]


class INT_L45_REPORT_FIXED(Packet):
    name = "INT_L45_REPORT_FIXED"
    fields_desc = [
        BitField("ver", 0, 4),
        BitField("nproto", 0, 4),
        BitField("d", 0, 1),
        BitField("q", 0, 1),
        BitField("f", 0, 1),
        BitField("rsvd", 0, 15),
        BitField("hw_id", 1, 6),
        XIntField("seq_no", 0),
        XIntField("ingress_tstamp", 0),
    ]


class INT_L45_FLOW_REPORT(Packet):
    name = "INT_L45_FLOW_REPORT"
    fields_desc = [
        XIntField("switch_id", 0),
        XShortField("ingress_port_id", 0),
        XShortField("egress_port_id", 0),
        BitField("queue_id", 0, 8),
        BitField("queue_occupancy", 0, 24),
        XIntField("egress_tstamp", 0),
    ]


class INT_L45_DROP_REPORT(Packet):
    name = "INT_L45_DROP_REPORT"
    fields_desc = [
        XIntField("switch_id", 0),
        XShortField("ingress_port_id", 0),
        XShortField("egress_port_id", 0),
        BitField("queue_id", 0, 8),
        XByteField("drop_reason", 0),
        ShortField("pad", 0),
    ]


bind_layers(UDP, INT_L45_REPORT_FIXED, dport=32766)
bind_layers(INT_L45_REPORT_FIXED, INT_L45_DROP_REPORT, nproto=1)
bind_layers(INT_L45_REPORT_FIXED, INT_L45_FLOW_REPORT, nproto=2)
bind_layers(INT_L45_DROP_REPORT, Ether)
bind_layers(INT_L45_FLOW_REPORT, Ether)


def get_readable_int_report_str(pkt: Packet) -> str:
    if INT_L45_REPORT_FIXED not in pkt:
        return "No INT report in this packet"
    fixed_report = pkt[INT_L45_REPORT_FIXED]
    report_types = []
    if fixed_report.d:
        report_types.append("Drop")
    if fixed_report.q:
        report_types.append("Queue")
    if fixed_report.f:
        report_types.append("Flow")
    report_type = ", ".join(report_types)
    hw_id = fixed_report.hw_id
    seq_no = fixed_report.seq_no
    ig_tstamp = fixed_report.ingress_tstamp
    readable_int_info = "Type: {}, HW ID: {}, Seq: {}, Ingress time: {}"

    if INT_L45_FLOW_REPORT not in pkt:
        return readable_int_info.format(report_type, hw_id, seq_no, ig_tstamp)

    flow_report = pkt[INT_L45_FLOW_REPORT]
    sw_id = flow_report.switch_id
    ig_port = flow_report.ingress_port_id
    eg_port = flow_report.egress_port_id
    q_id = flow_report.queue_id
    q_oc = flow_report.queue_occupancy
    eg_tstamp = flow_report.egress_tstamp
    latency = eg_tstamp - ig_tstamp

    if latency < 0:
        # Fix the latency number
        latency += 2 ** 32

    readable_int_info += (
        ", Switch ID: {}, Ingress: {}, Egress: {}, "
        + "Queue: {}, Queue occupancy: {}, Egress time: {}, latency: {}"
    )
    return readable_int_info.format(
        report_type,
        hw_id,
        seq_no,
        ig_tstamp,
        sw_id,
        ig_port,
        eg_port,
        q_id,
        q_oc,
        eg_tstamp,
        latency,
    )


def analyze_report_pcap(pcap_file: str, total_flows_from_trace: int = 0) -> dict:
    pcap_reader = PcapReader(pcap_file)
    skipped = 0
    dropped = 0  # based on seq number
    prev_seq_no = {}  # HW ID -> seq number

    # Flow report
    flow_reports = 0
    five_tuple_to_prev_flow_report_time = {}  # 5-tuple -> latest report time
    flow_with_multiple_flow_reports = set()
    valid_flow_report_irgs = []
    bad_flow_report_irgs = []
    invalid_flow_report_irgs = []

    # Drop report
    drop_reports = 0
    five_tuple_to_prev_drop_report_time = {}  # 5-tuple -> latest report time
    flow_with_multiple_drop_reports = set()
    valid_drop_report_irgs = []
    bad_drop_report_irgs = []
    invalid_drop_report_irgs = []
    pkt_processed = 0
    while True:
        try:
            report_pkt = pcap_reader.read_packet()
        except EOFError:
            break
        except StopIteration:
            break
        pkt_processed += 1

        if INT_L45_REPORT_FIXED not in report_pkt:
            skipped += 1
            continue

        # packet enter time in nano seconds (32-bit)
        packet_enter_time = report_pkt[INT_L45_REPORT_FIXED].ingress_tstamp

        int_fix_report = report_pkt[INT_L45_REPORT_FIXED]
        if INT_L45_FLOW_REPORT in report_pkt:
            flow_reports += 1
            int_report = report_pkt[INT_L45_FLOW_REPORT]
            five_tuple_to_prev_report_time = five_tuple_to_prev_flow_report_time
            flow_with_multiple_reports = flow_with_multiple_flow_reports
            valid_report_irgs = valid_flow_report_irgs
            bad_report_irgs = bad_flow_report_irgs
            invalid_report_irgs = invalid_flow_report_irgs
        elif INT_L45_DROP_REPORT in report_pkt:
            drop_reports += 1
            int_report = report_pkt[INT_L45_DROP_REPORT]
            five_tuple_to_prev_report_time = five_tuple_to_prev_drop_report_time
            flow_with_multiple_reports = flow_with_multiple_drop_reports
            valid_report_irgs = valid_drop_report_irgs
            bad_report_irgs = bad_drop_report_irgs
            invalid_report_irgs = invalid_drop_report_irgs
        else:
            # TODO: handle queue report
            skipped += 1
            continue

        # Check the sequence number
        hw_id = int_fix_report.hw_id
        seq_no = int_fix_report.seq_no
        if hw_id in prev_seq_no:
            dropped += seq_no - prev_seq_no[hw_id] - 1
        prev_seq_no[hw_id] = seq_no

        # Curently we only process IPv4 packets, but we can process IPv6 if needed.
        if IP not in int_report:
            skipped += 1
            continue

        # Checks the internal packet
        # Here we skip packets that is not a TCP or UDP packet since they can be
        # fragmented or something else.

        if TCP in int_report:
            internal_l4 = int_report[TCP]
        elif UDP in int_report:
            internal_l4 = int_report[UDP]
        else:
            skipped += 1
            continue

        internal_ip = int_report[IP]
        five_tuple = (
            inet_aton(internal_ip.src),
            inet_aton(internal_ip.dst),
            int.to_bytes(internal_ip.proto, 1, "big"),
            int.to_bytes(internal_l4.sport, 2, "big"),
            int.to_bytes(internal_l4.dport, 2, "big"),
        )

        if five_tuple in five_tuple_to_prev_report_time:
            prev_report_time = five_tuple_to_prev_report_time[five_tuple]
            irg = packet_enter_time - prev_report_time
            # timestamp overflow
            if irg < 0:
                irg += 0xFFFFFFFF
            irg /= 10 ** 9
            if irg != 0:
                valid_report_irgs.append(irg)
            else:
                invalid_report_irgs.append(irg)
            flow_with_multiple_reports.add(five_tuple)

            if 0 < irg and irg < 0.9:
                bad_report_irgs.append(irg)

        five_tuple_to_prev_report_time[five_tuple] = packet_enter_time

    results = {
        'pkt_processed': pkt_processed,
        'flow_reports': flow_reports,
        'five_tuple_to_prev_flow_report_time': len(five_tuple_to_prev_flow_report_time),
        'flow_with_multiple_flow_reports': len(flow_with_multiple_flow_reports),
        'valid_flow_report_irgs': len(valid_flow_report_irgs),
        'bad_flow_report_irgs': len(bad_flow_report_irgs),
        'invalid_flow_report_irgs': len(invalid_flow_report_irgs),
        'drop_reports': drop_reports,
        'five_tuple_to_prev_drop_report_time': len(five_tuple_to_prev_drop_report_time),
        'flow_with_multiple_drop_reports': len(flow_with_multiple_drop_reports),
        'valid_drop_report_irgs': len(valid_drop_report_irgs),
        'bad_drop_report_irgs': len(bad_drop_report_irgs),
        'invalid_drop_report_irgs': len(invalid_drop_report_irgs),
        'dropped': dropped,
        'skipped': skipped
    }

    print("Pkt processed: {}".format(pkt_processed))
    # Flow report
    print("Flow reports: {}".format(flow_reports))
    print("Total 5-tuples: {}".format(len(five_tuple_to_prev_flow_report_time)))
    print(
        "Flows with multiple report: {}".format(len(flow_with_multiple_flow_reports))
    )
    print("Total INT IRGs: {}".format(len(valid_flow_report_irgs)))
    print("Total bad INT IRGs(<0.9s): {}".format(len(bad_flow_report_irgs)))
    print(
        "Total invalid INT IRGs(<=0s): {}".format(len(invalid_flow_report_irgs))
    )
    if total_flows_from_trace != 0:
        accuracy_score = len(five_tuple_to_prev_flow_report_time) * 100 / total_flows_from_trace
        print(
            "Accuracy score: {}".format(accuracy_score)
        )
        results['accuracy_score'] = accuracy_score

    if len(valid_flow_report_irgs) <= 0:
        print("No valid flow report IRGs")
    else:
        efficiency_score = (len(valid_flow_report_irgs) - len(bad_flow_report_irgs)) * 100 / len(valid_flow_report_irgs)
        print(
            "Efficiency score: {}".format(efficiency_score)
        )
        results['efficiency_score'] = efficiency_score

        # Plot Histogram and CDF
        report_plot_file = abspath(splitext(pcap_file)[0] + "-local" + ".png")
        plot_histogram_and_cdf(report_plot_file, valid_flow_report_irgs)

    # Drop report
    print("----------------------")
    print("Drop reports: {}".format(drop_reports))
    print("Total 5-tuples: {}".format(len(five_tuple_to_prev_drop_report_time)))
    print(
        "Flows with multiple report: {}".format(len(flow_with_multiple_drop_reports))
    )
    print("Total INT IRGs: {}".format(len(valid_drop_report_irgs)))
    print("Total bad INT IRGs(<0.9s): {}".format(len(bad_drop_report_irgs)))
    print(
        "Total invalid INT IRGs(<=0s): {}".format(len(invalid_drop_report_irgs))
    )
    print("Total report dropped: {}".format(dropped))
    print("Skipped packets: {}".format(skipped))

    if len(valid_drop_report_irgs) <= 0:
        print("No valid drop report IRGs")
    else:
        print(
            "Efficiency score: {}".format(
                (len(valid_drop_report_irgs) - len(bad_drop_report_irgs))
                * 100
                / len(valid_drop_report_irgs)
            )
        )
        report_plot_file = abspath(splitext(pcap_file)[0] + "-drop" + ".png")
        plot_histogram_and_cdf(report_plot_file, valid_drop_report_irgs)
    
    return results


def plot_histogram_and_cdf(report_plot_file, valid_report_irgs):
    if exists(report_plot_file):
        os.remove(report_plot_file)
    bin_size = 0.25  # sec
    max_val = max(np.max(valid_report_irgs), 3)
    percentile_of_900_msec = stats.percentileofscore(valid_report_irgs, 0.9)
    percentile_of_one_sec = stats.percentileofscore(valid_report_irgs, 1)
    percentile_of_two_sec = stats.percentileofscore(valid_report_irgs, 2)
    percentiles = [
        1,
        5,
        10,
        percentile_of_900_msec,
        percentile_of_one_sec,
        percentile_of_two_sec,
    ]
    vlines = np.percentile(valid_report_irgs, percentiles)

    bins = np.arange(0, max_val + bin_size, bin_size)
    hist, bins = np.histogram(valid_report_irgs, bins=bins)

    # to percentage
    hist = hist / hist.sum()

    CY = np.cumsum(hist)

    _, ax = plt.subplots(figsize=(10, 10))

    fig_y_max = percentile_of_two_sec / 100 + 0.1
    ax.set_yticks(np.arange(0, fig_y_max, 0.1))
    ax.hlines(np.arange(0, fig_y_max, 0.1), 0, 2, colors="y", linestyles=["dotted"])
    ax.vlines(vlines, 0, 1, colors="green", linestyles=["dotted"])

    t = int(2 / bin_size) + 1  # 2 sec -> 8+1 bins
    ax.plot(bins[:t], hist[:t])
    ax.plot(bins[:t], CY[:t], "r--")

    for i in range(0, len(vlines)):
        x = vlines[i]
        y = percentiles[i] / 100
        ax.text(x, y, "({:.2f}%: {:.2f})".format(percentiles[i], x))

    plt.savefig(report_plot_file)
    print(
        "Histogram and CDF graph can be found here: {}".format(report_plot_file)
    )
    return report_plot_file
