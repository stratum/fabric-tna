# SPDX-FileCopyrightText: Copyright 2020-present Open Networking Foundation.
# SPDX-License-Identifier: Apache-2.0
import logging
import os
from os.path import abspath, exists, splitext

import matplotlib.pyplot as plt
import numpy as np
from scapy.fields import BitField, ShortField, XByteField, XIntField, XShortField
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Packet, bind_layers
from scapy.utils import RawPcapReader, inet_aton
from scipy import stats

log = logging.getLogger("INT Util")
log.setLevel(logging.INFO)


class IntMetaHdr(Packet):
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


class IntL45Head(Packet):
    name = "INT_L45_HEAD"
    fields_desc = [
        XByteField("int_type", 0x01),
        XByteField("rsvd0", 0x00),
        XByteField("length", 0x00),
        XByteField("rsvd1", 0x00),
    ]


class IntL45Tail(Packet):
    name = "INT_L45_TAIL"
    fields_desc = [
        XByteField("next_proto", 0x01),
        XShortField("proto_param", 0x0000),
        XByteField("rsvd", 0x00),
    ]


class IntL45ReportFixed(Packet):
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


class IntL45LocalReport(Packet):
    name = "INT_L45_LOCAL_REPORT"
    fields_desc = [
        XIntField("switch_id", 0),
        XShortField("ingress_port_id", 0),
        XShortField("egress_port_id", 0),
        BitField("queue_id", 0, 8),
        BitField("queue_occupancy", 0, 24),
        XIntField("egress_tstamp", 0),
    ]


bind_layers(UDP, IntL45ReportFixed, dport=32766)
bind_layers(IntL45ReportFixed, IntL45LocalReport, nproto=2)
bind_layers(IntL45LocalReport, Ether)


def get_readable_int_report_str(pkt: Packet) -> str:
    if IntL45ReportFixed not in pkt:
        return "No INT report in this packet"
    fixed_report = pkt[IntL45ReportFixed]
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

    if IntL45LocalReport not in pkt:
        return readable_int_info.format(report_type, hw_id, seq_no, ig_tstamp)

    local_report = pkt[IntL45LocalReport]
    sw_id = local_report.switch_id
    ig_port = local_report.ingress_port_id
    eg_port = local_report.egress_port_id
    q_id = local_report.queue_id
    q_oc = local_report.queue_occupancy
    eg_tstamp = local_report.egress_tstamp
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


def analysis_report_pcap(pcap_file: str, total_flows_from_trace: int = 0) -> str:
    pcap_reader = RawPcapReader(pcap_file)
    total_reports = 0
    skipped = 0
    dropped = 0  # based on seq number
    prev_seq_no = {}  # HW ID -> seq number
    five_tuple_to_prev_report_time = {}  # 5-tuple -> latest report time
    flow_with_multiple_reports = set()
    valid_irgs = []
    bad_irgs = []
    invalid_irgs = []

    while True:
        # import pdb; pdb.set_trace()
        try:
            packet_info = pcap_reader.next()
        except EOFError:
            break
        except StopIteration:
            break

        # packet_info = (raw-bytes, packet-metadata)
        report_pkt = Ether(packet_info[0])

        if IntL45ReportFixed not in report_pkt:
            skipped += 1
            continue

        if IntL45LocalReport not in report_pkt:
            # TODO: handle drop and queue report
            skipped += 1
            continue

        int_fix_report = report_pkt[IntL45ReportFixed]
        int_local_report = report_pkt[IntL45LocalReport]

        # Check the sequence number
        hw_id = int_fix_report.hw_id
        seq_no = int_fix_report.seq_no
        if hw_id in prev_seq_no:
            dropped += seq_no - prev_seq_no[hw_id] - 1
        prev_seq_no[hw_id] = seq_no

        # Checks the internal packet
        # Here we skip packets that is not a TCP or UDP packet since they can be
        # fragmented or something else.

        if TCP in int_local_report:
            internal_l4 = int_local_report[TCP]
        elif UDP in int_local_report:
            internal_l4 = int_local_report[UDP]
        else:
            skipped += 1
            continue

        # Curently we only process IPv4 packets, but we can process IPv6 if needed.
        if IP not in int_local_report:
            skipped += 1
            continue

        internal_ip = int_local_report[IP]
        five_tuple = (
            inet_aton(internal_ip.src)
            + inet_aton(internal_ip.dst)
            + int.to_bytes(internal_ip.proto, 1, "big")
            + int.to_bytes(internal_l4.sport, 2, "big")
            + int.to_bytes(internal_l4.dport, 2, "big")
        )

        if five_tuple in five_tuple_to_prev_report_time:
            prev_report_time = five_tuple_to_prev_report_time[five_tuple]
            irg = (int_local_report.egress_tstamp - prev_report_time) / 1000000000
            if irg > 0:
                valid_irgs.append(irg)
            flow_with_multiple_reports.add(five_tuple)

            if 0 < irg and irg < 0.9:
                bad_irgs.append(irg)
            if irg <= 0:
                invalid_irgs.append(irg)

        five_tuple_to_prev_report_time[five_tuple] = int_local_report.egress_tstamp
        total_reports += 1

    log.info("Reports processed: {}".format(total_reports))
    log.info("Skipped packets: {}".format(skipped))
    total_five_tuples = len(five_tuple_to_prev_report_time)
    log.info("Total 5-tuples: {}".format(total_five_tuples))
    log.info(
        "Flows with single report: {}".format(
            total_five_tuples - len(flow_with_multiple_reports)
        )
    )
    log.info("Flows with multiple report: {}".format(len(flow_with_multiple_reports)))
    log.info("Total INT IRGs: {}".format(len(valid_irgs)))
    log.info("Total bad INT IRGs(<0.9s): {}".format(len(bad_irgs)))
    log.info("Total invalid INT IRGs(<=0s): {}".format(len(invalid_irgs)))
    log.info("Total report dropped: {}".format(dropped))

    if total_flows_from_trace != 0:
        log.info(
            "Accuracy score: {}".format(
                total_five_tuples * 100 / total_flows_from_trace
            )
        )

    if len(valid_irgs) <= 0:
        log.info("No valid IRGs")
        return

    log.info(
        "Efficiency score: {}".format(
            (len(valid_irgs) - len(bad_irgs)) * 100 / len(valid_irgs)
        )
    )

    # Plot Histogram and CDF
    report_plot_file = abspath(splitext(pcap_file)[0] + ".png")
    if exists(report_plot_file):
        os.remove(report_plot_file)
    bin_size = 0.25  # sec
    max_val = max(np.max(valid_irgs), 3)
    percentile_of_900_msec = stats.percentileofscore(valid_irgs, 0.9)
    percentile_of_one_sec = stats.percentileofscore(valid_irgs, 1)
    percentile_of_two_sec = stats.percentileofscore(valid_irgs, 2)
    percentiles = [
        1,
        5,
        10,
        percentile_of_900_msec,
        percentile_of_one_sec,
        percentile_of_two_sec,
    ]
    vlines = np.percentile(valid_irgs, percentiles)

    bins = np.arange(0, max_val + bin_size, bin_size)
    hist, bins = np.histogram(valid_irgs, bins=bins)

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
    log.info("Histogram and CDF graph can be found here: {}".format(report_plot_file))
    return report_plot_file
