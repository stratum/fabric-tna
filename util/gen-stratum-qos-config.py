#!/usr/bin/env python3
# Copyright 2021-present Open Networking Foundation
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
# -*- utf-8 -*-
"""
Generates a snippet of Stratum's chassis_config file with the vendor_config for Tofino that realizes
the SD-Fabric slicing/QoS model.

Usage:

./gen-stratum-qos-config.py qos-model.yml
"""

from math import ceil, floor

GBPS = 10 ** 9
MBPS = 10 ** 6
MB = 10 ** 6
MS = 10 ** -3
NEW_LINE = "\n"

DEFAULT_MTU_BYTES = 1500
MAX_CELLS = 280000  # 22MB
CELL_BYTES = 80
# Minimum guaranteed bandwidth for the Best-Effort CoS.
BE_MIN_RATE_BPS = 10 * MBPS
# Maximum bandwidth for the System CoS.
SYS_MAX_RATE_BPS = 10 * MBPS
# Control CoS golden rule: never exceed the given link utilization to avoid excessive delay for low
# priority queues.
CTRL_MAX_UTIL = 0.10


def format_bps(bps):
    """
    Return a human-friendly bitrate string.
    :param bps: value in bits per second
    :return: string
    """
    n = 0
    power_labels = {0: '', 1: 'K', 2: 'M', 3: 'G', 4: 'T'}
    while bps > 1000:
        bps /= 1000
        n += 1
    return f"{round(size, 1)}{power_labels[n]}bps"


def queue_mapping(descr, queue_id, prio, weight, min_cells, app_pool,
                  max_rate=0, max_rate_is_pps="false", max_burst=0):
    """
    Prints a queue mapping.
    """
    # TODO (carmelo): figure out a meaningful setting for base_use_limit, baf, and hysteresis.
    return f"""        queue_mapping {{
            # {descr}
            queue_id: {queue_id}
            priority: PRIO_{prio}
            weight: {weight}
            minimum_guaranteed_cells: {min_cells}
            pool: EGRESS_APP_POOL_{app_pool}
            base_use_limit: 200
            baf: BAF_80_PERCENT
            hysteresis: 50
            min_rate_is_enabled: {"true" if max_rate else "false"}
            max_rate_is_in_pps: {max_rate_is_pps}
            max_rate: {max_rate}
            max_burst: {int(max_burst)}
            min_rate_is_enabled: false
        }}"""


def queue_config(descr, sdk_port, port_rate_bps, port_queue_count, ct_count, ct_meter_rate_pps,
                 ct_meter_burst_pkts, ct_mtu_bytes, rt_max_rates_bps, rt_max_burst_s,
                 el_min_rates_bps):
    """
    Print the queue_config blob for the given port and slices' allocations.
    :param descr: a description of the port
    :param sdk_port: SDK port number (i.e., DP_ID)
    :param port_rate_bps: link capacity or port shaping rate if set
    :param port_queue_count: how many queues can be allocated to this port
    :param ct_count: number of Control slots, each slice an use one or more slots
    :param ct_meter_rate_pps: metering rate for each Control slot (in pps)
    :param ct_meter_burst_pkts: metering burst size for each Control slot (in pkts)
    :param ct_mtu_bytes: maximum transmission unit allowed for Control traffic
    :param rt_max_rates_bps: list of max shaping rates for Real-Time slices, one for each slice
    :param rt_max_burst_s: maximum amount of time that a Real-Time slice is allowed to burst
    :param el_min_rates_bps: list of min guaranteed rates for Elastic slices, one for each slice
    :return: prints the queue_config blob
    """
    queue_mappings = []

    # -- CONTROL
    # All Control slices share the same queue. Ingress meters (configured via P4Runtime) are used to
    # prevent abuse by misbehaving senders. The available bandwidth dedicated to Control traffic is
    # partitioned in slot. Each slot has a maximum rate and burst (in packets). Each slice can use
    # one or more slots.
    ct_queue_min_cells = ceil((ct_count * ct_meter_burst_pkts * ct_mtu_bytes) / CELL_BYTES)
    ct_queue_max_rate_pps = ct_meter_rate_pps * ct_count
    ct_queue_max_burst_pkts = ct_meter_burst_pkts * ct_count
    ct_util = (ct_count * ct_meter_rate_pps * ct_mtu_bytes * 8) / port_rate_bps
    assert ct_util < CTRL_MAX_UTIL, \
        f"Port utilization for the Control CoS exceeds the maximum threshold: " \
        f"requested={ct_util}, " \
        f"available={CTRL_MAX_UTIL}"

    queue_mappings.append(queue_mapping(
        descr=f"Control ({ct_count} slots @ "
              f"{ct_meter_rate_pps}pps, {ct_meter_burst_pkts}pkts burst)",
        queue_id=0,
        prio=7,
        weight=1,
        min_cells=ct_queue_min_cells,
        app_pool=0,
        max_rate_is_pps="true",
        max_rate=ct_queue_max_rate_pps,
        max_burst=ct_queue_max_burst_pkts
    ))

    # -- REAL-TIME
    # Each slice requesting Real-Time CoS gets a dedicated queue, dimensioned to handle the given
    # max rate and burst duration. System is treated as a Real-Time queue.
    rt_max_rates_bps.append(SYS_MAX_RATE_BPS)
    rt_max_burst_bytes = port_rate_bps * rt_max_burst_s / 8
    rt_queue_min_cells = ceil(rt_max_burst_bytes / CELL_BYTES)
    rt_link_util = sum(rt_max_rates_bps) / port_rate_bps
    rt_avail_bw_bps = (1 - ct_util) * port_rate_bps
    assert sum(rt_max_rates_bps) < rt_avail_bw_bps, \
        "Not enough bandwidth to allocate Real-Time slices: " \
        f"requested={format_bps(sum(rt_max_rates_bps))}, " \
        f"available={format_bps(ct_util * port_rate_bps)}"

    next_queue_id = 1
    for i in range(len(rt_max_rates_bps)):
        if i == len(rt_max_rates_bps) - 1:
            # Last one is System
            name = f"System"
        else:
            name = f"Real-Time {i + 1}"
        queue_mappings.append(queue_mapping(
            descr=f"{name} ({format_bps(rt_max_rates_bps[i])}, "
                  f"{rt_max_burst_s}s burst)",
            queue_id=next_queue_id,
            prio=6,
            weight=1,
            min_cells=rt_queue_min_cells,
            app_pool=0,
            max_rate_is_pps="false",
            max_rate=ceil(rt_max_rates_bps[i] / 8),  # bytes per second
            max_burst=rt_max_burst_bytes
        ))
        next_queue_id += 1

    # -- ELASTIC
    # Each slice requesting Elastic CoS gets a dedicated queue, dimensioned to guarantee the given
    # minimum rate during congestion. Best-Effort is treated as an Elastic queues.
    el_min_rates_bps.append(BE_MIN_RATE_BPS)
    el_weights = [ceil(1024 * x / sum(el_min_rates_bps)) for x in el_min_rates_bps]
    el_avail_bw_bps = (1 - rt_link_util - ct_util) * port_rate_bps
    assert sum(el_min_rates_bps) <= el_avail_bw_bps, \
        f"Not enough bandwidth to allocate Elastic slices: " \
        f"requested={format_bps(sum(el_min_rates_bps))}, " \
        f"available={format_bps(el_avail_bw_bps)}"

    for i in range(len(el_min_rates_bps)):
        if i == len(el_min_rates_bps) - 1:
            # Last one is Best-Effort
            name = "Best-Effort"
            app_pool = 1
        else:
            name = f"Elastic {i + 1}"
            app_pool = 2
        queue_mappings.append(queue_mapping(
            descr=f"{name} ({format_bps(el_min_rates_bps[i])})",
            queue_id=next_queue_id,
            prio=0,
            # TODO (carmelo): make sure we can enforce byte-mode for WRR scheduling
            weight=el_weights[i],
            min_cells=100,
            app_pool=app_pool,
            max_rate=0,
        ))
        next_queue_id += 1

    used_queues = 1 + len(rt_max_rates_bps) + len(el_min_rates_bps)
    assert used_queues <= port_queue_count, \
        "Not enough queues: " \
        f"requested={used_queues}, " \
        f"available={port_queue_count}"

    print(f"""    queue_configs {{
        # {descr} ({used_queues} queues)
        sdk_port: {sdk_port}\n{NEW_LINE.join(queue_mappings)}
    }}""")


def pool_config(pool, size, enable_color_drop, limit_yellow, limit_red):
    """
    Prints a pool_configs blob with the given parameters.
    :param pool: pool number (0-4)
    :param size: number of cells allocated to this pool
    :param enable_color_drop: whether to enable color-ware dropping
    :param limit_yellow: number of used cells after which yellow packets will be dropped
    :param limit_red: number of cells after which red packets will be dropped
    :return:
    """
    print(f"""    pool_configs {{
        pool: EGRESS_APP_POOL_{pool}
        pool_size: {size}
        enable_color_drop: {enable_color_drop}
        color_drop_limit_green: {size}
        color_drop_limit_yellow: {limit_yellow}
        color_drop_limit_red: {limit_red}
    }}""")

# Below from here is for testing only.
# TODO (carmelo): pass all parameters at runtime, e.g., using yaml file with
#  high-level parameters

# TODO (carmelo): set port shaping rate (if different than channel speed)


pool_allocations = [0.10, 0.85, 0.05]
assert sum(pool_allocations) == 1, \
    f"Invalid total pool allocation: " \
    f"expected=1, actual={sum(pool_allocations)}"

for pool in range(len(pool_allocations)):
    size = floor(pool_allocations[pool] * MAX_CELLS)
    pool_config(
        pool=pool,
        size=size,
        enable_color_drop="true",
        limit_yellow=floor(0.90 * size),
        limit_red=floor(0.80 * size),
    )

queue_config(
    descr="Base station",
    sdk_port=268,
    port_rate_bps=1 * GBPS,
    port_queue_count=16,
    ct_count=50,
    ct_meter_rate_pps=100,
    ct_meter_burst_pkts=10,
    ct_mtu_bytes=DEFAULT_MTU_BYTES,
    rt_max_rates_bps=[30 * MBPS, 30 * MBPS, 20 * MBPS],
    rt_max_burst_s=5 * MS,
    el_min_rates_bps=[100 * MBPS, 200 * MBPS, 300 * MBPS]
)

queue_config(
    descr="Server/spine",
    sdk_port=269,
    port_rate_bps=40 * GBPS,
    port_queue_count=32,
    ct_count=50,
    ct_meter_rate_pps=100,
    ct_meter_burst_pkts=10,
    ct_mtu_bytes=DEFAULT_MTU_BYTES,
    rt_max_rates_bps=[30 * MBPS, 30 * MBPS, 20 * MBPS],
    rt_max_burst_s=5 * MS,
    el_min_rates_bps=[100 * MBPS, 200 * MBPS, 300 * MBPS]
)

queue_config(
    descr="Upstream router",
    sdk_port=270,
    port_rate_bps=10 * GBPS,
    port_queue_count=32,
    ct_count=50,
    ct_meter_rate_pps=100,
    ct_meter_burst_pkts=10,
    ct_mtu_bytes=DEFAULT_MTU_BYTES,
    rt_max_rates_bps=[30 * MBPS, 30 * MBPS, 20 * MBPS],
    rt_max_burst_s=5 * MS,
    el_min_rates_bps=[100 * MBPS, 200 * MBPS, 300 * MBPS]
)
