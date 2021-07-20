# SPDX-FileCopyrightText: Copyright 2020-present Open Networking Foundation.
# SPDX-License-Identifier: Apache-2.0
import argparse
import logging
import collections

# Multiplier for data rates
K = 1000
M = K * 1000
G = M * 1000

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
        logging.info("States from port {}: \n{}".format(port, readable_stats))

LatencyStats = collections.namedtuple("LatencyStats", [
    "jitter",
    "average",
    "total_max",
    "total_min",
    "last_max",
    "histogram",
    "total_tx",
    "total_rx",
    "dropped",
    "out_of_order",
    "duplicate",
    "seq_too_high",
    "seq_too_low",
])

def get_latency_stats(pg_id: int, stats) -> LatencyStats:
    flow_stats = stats["flow_stats"].get(pg_id)
    lat_stats = stats['latency'].get(pg_id)
    lat = lat_stats['latency']

    ret = LatencyStats(
        jitter = lat['jitter'],
        average = lat['average'],
        total_max = lat['total_max'],
        total_min = lat['total_min'],
        last_max = lat['last_max'],
        histogram = lat['histogram'],
        total_tx = flow_stats['tx_pkts']['total'],
        total_rx = flow_stats['rx_pkts']['total'],
        dropped = lat_stats['err_cntrs']['dropped'],
        out_of_order = lat_stats['err_cntrs']['out_of_order'],
        duplicate = lat_stats['err_cntrs']['dup'],
        seq_too_high = lat_stats['err_cntrs']['seq_too_high'],
        seq_too_low = lat_stats['err_cntrs']['seq_too_low'],
    )
    return ret

def get_readable_latency_stats(pg_id: int, stats: LatencyStats) -> str:
    histogram = ""
    l = list(stats.histogram.keys()) # need to listify in order to be able to sort them.
    l.sort()
    for sample in l:
        range_start = sample
        if range_start == 0:
            range_end = 10
        else:
            range_end  = range_start + pow(10, (len(str(range_start))-1))
        val = stats.histogram[sample]
        histogram = histogram + "\n        Packets with latency between {0} us and {1} us: {2}".format(range_start, range_end, val)

    return f"""
    Latency info for pg_id {pg_id}
    Dropped packets: {stats.dropped}
    Out-of-order packets: {stats.out_of_order}
    Maximum latency: {stats.total_max} us
    Minimum latency: {stats.total_min} us
    Maximum latency in last sampling period: {stats.last_max} us
    Average latency: {stats.average} us
    Jitter: {stats.jitter} us
    Latency distribution histogram: {histogram}
    """

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
