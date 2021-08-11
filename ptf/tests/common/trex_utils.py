# SPDX-FileCopyrightText: Copyright 2020-present Open Networking Foundation.
# SPDX-License-Identifier: Apache-2.0
import argparse
import collections
import logging

import numpy as np

# Multiplier for data rates
from fabric_test import IP_HDR_BYTES, UDP_HDR_BYTES
from trex.stl.trex_stl_packet_builder_scapy import (
    STLScVmRaw,
    STLVmFixIpv4,
    STLVmFlowVar,
    STLVmTrimPktSize,
    STLVmWrFlowVar,
)

K = 1000
M = 1000 * K
G = 1000 * M


def to_readable(src: int, unit: str = "bps") -> str:
    """
    Convert number to human readable string.
    For example: 1,000,000 bps to 1Mbps. 1,000 bytes to 1KB

    :parameters:
        src : int
            the original data
        unit : str
            the unit ('bps', 'pps', or 'bytes')
    :returns:
        A human readable string
    """
    if src < 1000:
        return "{:.1f} {}".format(src, unit)
    elif src < 1000_000:
        return "{:.1f} K{}".format(src / 1000, unit)
    elif src < 1000_000_000:
        return "{:.1f} M{}".format(src / 1000_000, unit)
    else:
        return "{:.1f} G{}".format(src / 1000_000_000, unit)


def get_readable_port_stats(port_stats: str) -> str:
    opackets = port_stats.get("opackets", 0)
    ipackets = port_stats.get("ipackets", 0)
    obytes = port_stats.get("obytes", 0)
    ibytes = port_stats.get("ibytes", 0)
    oerrors = port_stats.get("oerrors", 0)
    ierrors = port_stats.get("ierrors", 0)
    tx_bps = port_stats.get("tx_bps", 0)
    tx_pps = port_stats.get("tx_pps", 0)
    tx_bps_L1 = port_stats.get("tx_bps_L1", 0)
    tx_util = port_stats.get("tx_util", 0)
    rx_bps = port_stats.get("rx_bps", 0)
    rx_pps = port_stats.get("rx_pps", 0)
    rx_bps_L1 = port_stats.get("rx_bps_L1", 0)
    rx_util = port_stats.get("rx_util", 0)
    return """
    Output packets: {}
    Input packets: {}
    Output bytes: {} ({})
    Input bytes: {} ({})
    Output errors: {}
    Input errors: {}
    TX bps: {} ({})
    TX pps: {} ({})
    L1 TX bps: {} ({})
    TX util: {}
    RX bps: {} ({})
    RX pps: {} ({})
    L1 RX bps: {} ({})
    RX util: {}""".format(
        opackets,
        ipackets,
        obytes,
        to_readable(obytes, "Bytes"),
        ibytes,
        to_readable(ibytes, "Bytes"),
        oerrors,
        ierrors,
        tx_bps,
        to_readable(tx_bps),
        tx_pps,
        to_readable(tx_pps, "pps"),
        tx_bps_L1,
        to_readable(tx_bps_L1),
        tx_util,
        rx_bps,
        to_readable(rx_bps),
        rx_pps,
        to_readable(rx_pps, "pps"),
        rx_bps_L1,
        to_readable(rx_bps_L1),
        rx_util,
    )


def list_port_status(port_status: dict) -> None:
    """
    List all port status

    :parameters:
    port_status: dict
        Port status from Trex client API
    """
    for port in [0, 1, 2, 3]:
        readable_stats = get_readable_port_stats(port_status[port])
        print("States from port {}: \n{}".format(port, readable_stats))


LatencyStats = collections.namedtuple(
    "LatencyStats",
    [
        "pg_id",
        "jitter",
        "average",
        "total_max",
        "total_min",
        "last_max",
        "histogram",
        "dropped",
        "out_of_order",
        "duplicate",
        "seq_too_high",
        "seq_too_low",
        "percentile_50",
        "percentile_75",
        "percentile_90",
        "percentile_99",
        "percentile_99_9",
        "percentile_99_99",
        "percentile_99_999",
    ],
)

FlowStats = collections.namedtuple(
    "FlowStats", ["pg_id", "tx_packets", "rx_packets", "tx_bytes", "rx_bytes",         "tx_pkts_share",
        "rx_pkts_share",
        "tx_bytes_share",
        "rx_bytes_share",],
)


PortStats = collections.namedtuple(
    "PortStats",
    [
        "tx_packets",
        "rx_packets",
        "tx_bytes",
        "rx_bytes",
        "tx_errors",
        "rx_errors",
        "tx_bps",
        "tx_pps",
        "tx_bps_L1",
        "tx_util",
        "rx_bps",
        "rx_pps",
        "rx_bps_L1",
        "rx_util",
    ],
)


def get_port_stats(port: int, stats) -> PortStats:
    port_stats = stats.get(port)
    return PortStats(
        tx_packets=port_stats.get("opackets", 0),
        rx_packets=port_stats.get("ipackets", 0),
        tx_bytes=port_stats.get("obytes", 0),
        rx_bytes=port_stats.get("ibytes", 0),
        tx_errors=port_stats.get("oerrors", 0),
        rx_errors=port_stats.get("ierrors", 0),
        tx_bps=port_stats.get("tx_bps", 0),
        tx_pps=port_stats.get("tx_pps", 0),
        tx_bps_L1=port_stats.get("tx_bps_L1", 0),
        tx_util=port_stats.get("tx_util", 0),
        rx_bps=port_stats.get("rx_bps", 0),
        rx_pps=port_stats.get("rx_pps", 0),
        rx_bps_L1=port_stats.get("rx_bps_L1", 0),
        rx_util=port_stats.get("rx_util", 0),
    )


def get_latency_stats(pg_id: int, stats) -> LatencyStats:
    lat_stats = stats["latency"].get(pg_id)
    lat = lat_stats["latency"]
    # Estimate latency percentiles from the histogram.
    l = list(lat["histogram"].keys())
    l.sort()
    all_latencies = []
    for sample in l:
        range_start = sample
        if range_start == 0:
            range_end = 10
        else:
            range_end = range_start + pow(10, (len(str(range_start)) - 1))
        val = lat["histogram"][sample]
        # Assume whole the bucket experienced the range_end latency.
        all_latencies += [range_end] * val
    q = [50, 75, 90, 99, 99.9, 99.99, 99.999]
    percentiles = np.percentile(all_latencies, q)

    ret = LatencyStats(
        pg_id=pg_id,
        jitter=lat["jitter"],
        average=lat["average"],
        total_max=lat["total_max"],
        total_min=lat["total_min"],
        last_max=lat["last_max"],
        histogram=lat["histogram"],
        dropped=lat_stats["err_cntrs"]["dropped"],
        out_of_order=lat_stats["err_cntrs"]["out_of_order"],
        duplicate=lat_stats["err_cntrs"]["dup"],
        seq_too_high=lat_stats["err_cntrs"]["seq_too_high"],
        seq_too_low=lat_stats["err_cntrs"]["seq_too_low"],
        percentile_50=percentiles[0],
        percentile_75=percentiles[1],
        percentile_90=percentiles[2],
        percentile_99=percentiles[3],
        percentile_99_9=percentiles[4],
        percentile_99_99=percentiles[5],
        percentile_99_999=percentiles[6],
    )
    return ret


def get_readable_latency_stats(stats: LatencyStats) -> str:
    histogram = ""
    # need to listify in order to be able to sort them.
    l = list(stats.histogram.keys())
    l.sort()
    for sample in l:
        range_start = sample
        if range_start == 0:
            range_end = 10
        else:
            range_end = range_start + pow(10, (len(str(range_start)) - 1))
        val = stats.histogram[sample]
        histogram = (
            histogram
            + "\n        Packets with latency between {0:>5} us and {1:>5} us: {2:>10}".format(
                range_start, range_end, val
            )
        )

    return f"""
    Latency info for pg_id {stats.pg_id}
    Dropped packets: {stats.dropped}
    Out-of-order packets: {stats.out_of_order}
    Sequence too high packets: {stats.seq_too_high}
    Sequence too low packets: {stats.seq_too_low}
    Maximum latency: {stats.total_max} us
    Minimum latency: {stats.total_min} us
    Maximum latency in last sampling period: {stats.last_max} us
    Average latency: {stats.average} us
    50th percentile latency: {stats.percentile_50} us
    75th percentile latency: {stats.percentile_75} us
    90th percentile latency: {stats.percentile_90} us
    99th percentile latency: {stats.percentile_99} us
    99.9th percentile latency: {stats.percentile_99_9} us
    99.99th percentile latency: {stats.percentile_99_99} us
    99.999th percentile latency: {stats.percentile_99_999} us
    Jitter: {stats.jitter} us
    Latency distribution histogram: {histogram}
    """


def get_readable_flow_stats(stats: FlowStats) -> str:
    return f"""Flow info for pg_id {stats.pg_id}
    TX packets: {stats.tx_packets} ({stats.tx_pkts_share:.1%})
    RX packets: {stats.rx_packets} ({stats.rx_pkts_share:.1%})
    TX bytes: {stats.tx_bytes} ({stats.tx_bytes_share:.1%})
    RX bytes: {stats.rx_bytes} ({stats.rx_bytes_share:.1%})"""


def get_flow_stats(pg_id: int, stats) -> FlowStats:
    # Obtain sum from all pg_ids to compute shares
    sums = {}
    for metric in ["tx_pkts", "rx_pkts", "tx_bytes", "rx_bytes"]:
        sums[metric] = sum(
            [
                int(stats["flow_stats"][pg_id][metric]["total"])
                for pg_id in stats["flow_stats"]
                if pg_id != "global"
            ]
        )
    flow_stats = stats["flow_stats"].get(pg_id)
    ret = FlowStats(
        pg_id=pg_id,
        tx_packets=flow_stats["tx_pkts"]["total"],
        rx_packets=flow_stats["rx_pkts"]["total"],
        tx_bytes=flow_stats["tx_bytes"]["total"],
        rx_bytes=flow_stats["rx_bytes"]["total"],
        tx_pkts_share=flow_stats["tx_pkts"]["total"] / sums["tx_pkts"],
        rx_pkts_share=flow_stats["rx_pkts"]["total"] / sums["rx_pkts"],
        tx_bytes_share=flow_stats["tx_bytes"]["total"] / sums["tx_bytes"],
        rx_bytes_share=flow_stats["rx_bytes"]["total"] / sums["rx_bytes"],
    )
    return ret


# Returns a field engine to randomize packet size by trimming them
def get_random_pkt_trim_vm(max_l2_size, min_l2_size):
    l3_len_fix = -IP_HDR_BYTES
    l4_len_fix = -(IP_HDR_BYTES + UDP_HDR_BYTES)
    return STLScVmRaw(
        [
            # Create random variable
            STLVmFlowVar(
                name="fv_rand",
                min_value=min_l2_size,
                max_value=max_l2_size,
                size=2,
                op="random",
            ),
            # Trim pkt using random variable
            STLVmTrimPktSize("fv_rand"),
            # Fix IP len
            STLVmWrFlowVar(fv_name="fv_rand", pkt_offset="IP.len", add_val=l3_len_fix),
            # Fix IP checksum
            STLVmFixIpv4(offset="IP"),
            # Fix UDP len
            STLVmWrFlowVar(fv_name="fv_rand", pkt_offset="UDP.len", add_val=l4_len_fix),
        ]
    )


class ParseExtendArgAction(argparse.Action):
    def __init__(self, option_strings, dest, nargs=None, **kwargs):
        if nargs:
            raise ValueError("Action does not support nargs")
        super().__init__(option_strings, dest, nargs, **kwargs)

    def __call__(self, parser, namespace, value, option_string=None):
        # extending original dictionary
        if option_string != "-t" and option_string != "--test-args":
            raise KeyError("Inlvaud option string {}".format(option_string))

        if not namespace.test_args:
            namespace.test_args = {}

        if not value:
            raise ValueError("Value of {} cannot be empty".format(option_string))

        kv = value.split("=")
        if len(kv) != 2:
            raise ValueError("Invalid value: {}".format(value))
        key = value.split("=")[0]
        val = value.split("=")[1]
        namespace.test_args[key] = val
