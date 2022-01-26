#!/usr/bin/env python3
# Copyright 2021-present Open Networking Foundation
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
# -*- utf-8 -*-
"""
Generates QoS config snippets for ONOS and Stratum that realizes the SD-Fabric
slicing/QoS model for the given YAML input.

Usage:

    ./gen-qos-config.py -t <onos|stratum> sample-qos-config.yaml

Requirements:

    pip3 install pyyaml

Stratum:

 Generate the vendor_config block which is meant to be appended to an exiting
 chassis config file.

ONOS:

 Generate the slicing part of the fabric-tna app config.

"""
import argparse
import json
from math import ceil, floor

import yaml

GBPS = 10 ** 9  # gigabits per second
MBPS = 10 ** 6  # megabits per second
MB = 10 ** 6  # megabytes
MS = 10 ** -3  # milliseconds
NEW_LINE = "\n"

DEFAULT_MTU_BYTES = 1500
CELL_BYTES = 80

# Egress application pool numbers.
CT_APP_POOL = 0  # Control
RT_APP_POOL = 1  # Real-time
EL_APP_POOL = 2  # Elastic
BE_APP_POOL = 3  # Best-Effort

# Constant queue IDs. Other IDs will be allocated based on slices. Be careful
# when changing values, these are hard-coded in many other places.
QUEUE_ID_BEST_EFFORT = 0
QUEUE_ID_SYSTEM = 1
QUEUE_ID_CONTROL = 2

# Real-time and Elastic queues are allocated starting from this ID.
FIRST_QUEUE_ID = 3

# Queue priorities.
EL_PRIORITY = 0  # Elastic and Best-Effort (lowest)
RT_PRIORITY = 6  # Real-Time and System
CT_PRIORITY = 7  # Control (highest)

# Minimum guaranteed bandwidth for Best-Effort queue.
BE_MIN_RATE_BPS = 10 * MBPS
# Maximum allowed link utilization for the Control queue.
CT_MAX_UTIL = 0.10

# Default buffer absorption factor used for all queues (percentage of unused pool cells above
# base_use_limit).
DEFAULT_BAF_PERC = 33

DEFAULT_SLICE_ID = 0
DEFAULT_SLICE_NAME = "Default"


def format_bps(bps):
    """
    Return a human-friendly bitrate string.
    :param bps: value in bits per second
    :return: string
    """
    n = 0
    power_labels = {0: "", 1: "K", 2: "M", 3: "G", 4: "T"}
    while bps >= 1000:
        bps /= 1000
        n += 1
    return f"{round(bps, 1)}{power_labels[n]}bps"


def queue_mapping(
    descr,
    queue_id,
    prio,
    weight,
    app_pool,
    base_use_limit,
    baf,
    pool_size,
    max_rate_bps=0,
    max_burst_bytes=0,
    port_rate_bps=0,
):
    """
    Returns a queue mapping blob.
    :param descr: a description of the queue
    :param queue_id: queue ID (0-31)
    :param prio: scheduling priority (0-7)
    :param weight: scheduling weight (0-1023)
    :param app_pool: application pool number
    :param base_use_limit: number of pool cells
    :param baf: buffer absorption factor
    :param pool_size: the total number of cells in the pool
    :param max_rate_bps: maximum shaping rate in bps (0 means no limits, i.e., the queue can be
    serviced at the port rate)
    :param max_burst_bytes: maximum shaping burst size in bytes
    :param port_rate_bps: the port rate (link bandwidth or shaping rate)
    :return:
    """
    if max_rate_bps > 0:
        burst_ms = max_burst_bytes * 8 * 1000 / port_rate_bps
        max_rate = f"""max_rate_bytes {{
              rate_bps: {int(max_rate_bps)}
              burst_bytes: {int(max_burst_bytes)} # {burst_ms}ms
            }}"""
    else:
        max_rate = "# max_rate_bytes unset"

    queue_max_bytes = (base_use_limit + pool_size * baf / 100) * CELL_BYTES
    queue_max_mtus = floor(queue_max_bytes / DEFAULT_MTU_BYTES)

    return f"""          queue_mapping {{
            # {descr}
            queue_id: {queue_id}
            priority: PRIO_{prio}
            weight: {weight}
            minimum_guaranteed_cells: 0
            pool: EGRESS_APP_POOL_{app_pool}
            # Tail drop at {queue_max_mtus} MTUs or earlier
            base_use_limit: {base_use_limit}
            baf: BAF_{baf}_PERCENT
            hysteresis: 0
            {max_rate}
          }}"""


def queue_config(
    descr,
    port_id,
    is_sdk_port,
    port_rate_bps,
    port_queue_count,
    ct_slice_names,
    ct_max_rates_bps,
    ct_slot_rate_pps,
    ct_slot_burst_pkts,
    ct_mtu_bytes,
    rt_max_rates_bps,
    rt_max_burst_s,
    rt_slice_names,
    el_min_rates_bps,
    el_slice_names,
    port_rates_bps,
    pool_sizes,
    sys_max_rate_bps,
    used_pool_buls,
):
    """
    Returns the queue_config blob for the given port and slices' allocations.
    :param descr: a description of the port
    :param port_id: port ID
    :param is_sdk_port: true if port_id is an SDK port number (i.e., Tofino DP_ID),
        false if it's a SingletonPort ID from Stratum's chassis_config
    :param port_rate_bps: link capacity or port shaping rate if set
    :param port_queue_count: how many queues can be allocated to this port
    :param ct_slice_names: list of names of slices associated to Control tcs
    :param ct_max_rates_bps: list of max allowed rates for Control tcs, one for each slice
    :param ct_slot_rate_pps: metering rate for each Control slot (in pps)
    :param ct_slot_burst_pkts: metering burst size for each Control slot (in pkts)
    :param ct_mtu_bytes: maximum transmission unit allowed for Control traffic
    :param rt_max_rates_bps: list of max shaping rates for Real-Time tcs, one for each slice
    :param rt_slice_names: list of names of slices associated to Real-Time tcs
    :param rt_max_burst_s: maximum amount of time that a Real-Time queue is allowed to burst
    :param el_min_rates_bps: list of min guaranteed rates for Elastic slices, one for each slice
    :param el_slice_names: list of names of slices associated to Elastic tcs
    :param port_rates_bps: the list of rates (link bandwidth or port shaping) for all ports
    configured in this switch
    :param pool_sizes: the list of pool sizes (in cells)
    :param sys_max_rate_bps: shaping rate for the system queue
    :param used_pool_buls: control variable
    :return: the queue_config blob (text), dictionary with computed queue parameters
    """
    all_slice_names = set(ct_slice_names + rt_slice_names + el_slice_names)
    all_slice_names.add(DEFAULT_SLICE_NAME)
    all_params = {x: {} for x in all_slice_names}

    # Preallocate list as we will not populate it in order.
    queue_mappings = [None] * (3 + len(rt_max_rates_bps) + len(el_min_rates_bps))

    port_count = len(port_rates_bps)

    # -- CONTROL
    # All Control slices share the same queue. Ingress meters (configured via P4Runtime) are used to
    # prevent abuse by misbehaving senders. Packets over the meter threshold are dropped, or
    # redirected to the Best-Effort queue. As a consequence, the maximum number of packets that can
    # be in the Control queue at any given time is bounded.
    #
    # The available bandwidth dedicated to Control traffic is partitioned in "slots". Each slot has
    # a maximum rate and burst (in packets). Each slice can use one or more slots. Meters should
    # enforce rate limits depending on the number of slots associated with a slice.

    # Set maximum shaping rate to handle the worst case, where all slices send a burst of packets at
    # the same time. Check that the rate doesn't exceed the maximum utilization threshold to avoid
    # excessive delay for lower priority queues.
    # FIXME: slot-based computation no longer makes sense for the control queue.
    #  Find a simpler way to determine the burst limit of each slice.
    #  Maybe provide that in the yaml? Oo proportionally to the rate?
    ct_max_rate_bps = sum(ct_max_rates_bps)
    ct_util = ct_max_rate_bps / port_rate_bps
    assert ct_util < CT_MAX_UTIL, (
        f"Port utilization for the Control queue exceeds the maximum threshold: "
        f"requested={ct_util}, "
        f"available={CT_MAX_UTIL}"
    )

    ct_max_rate_pps = ceil(ct_max_rate_bps / (ct_mtu_bytes * 8))
    ct_slot_count = ceil(ct_max_rate_pps / ct_slot_rate_pps)
    ct_max_burst_pkts = ct_slot_burst_pkts * ct_slot_count
    ct_max_burst_bytes = ct_max_burst_pkts * ct_mtu_bytes

    # Divide the poll equally between all ports (since we have only one Control queue per port).
    ct_base_use_limit = floor(pool_sizes[CT_APP_POOL] / port_count)

    # Weight doesn't matter, this is the only queue in the WRR/priority group
    ct_wrr_weight = 1

    params = dict(
        descr=f"Shared Control ({ct_slot_count} slots, "
              f"{ct_slot_rate_pps}pps, {ct_slot_burst_pkts}MTUs burst, {ct_util} util)",
        queue_id=QUEUE_ID_CONTROL,
        app_pool=CT_APP_POOL,
        prio=CT_PRIORITY,
        weight=ct_wrr_weight,
        base_use_limit=ct_base_use_limit,
        baf=DEFAULT_BAF_PERC,
        pool_size=pool_sizes[BE_APP_POOL],
        max_rate_bps=ct_max_rate_bps,
        max_burst_bytes=ct_max_burst_bytes,
        port_rate_bps=port_rate_bps,
    )
    queue_mappings[QUEUE_ID_CONTROL] = queue_mapping(**params)
    for slice_name in ct_slice_names:
        all_params[slice_name]["control"] = params
    used_pool_buls[CT_APP_POOL] += ct_base_use_limit

    # -- REAL-TIME
    # Each slice requesting Real-Time service gets a dedicated queue, shaped to the given max rate
    # and burst. System is treated as a Real-Time queue.
    rt_max_rates_bps = rt_max_rates_bps.copy()
    rt_slice_names = rt_slice_names.copy()
    rt_max_rates_bps.append(sys_max_rate_bps)
    rt_slice_names.append(DEFAULT_SLICE_NAME)

    # To simplify configuration, we allow expressing the maximum queue shaping burst as a duration,
    # but we set the corresponding value in bytes (based on the port rate).
    # IMPORTANT: rt_max_burst_s should not be intended as the maximum amount of time that a
    # Real-Time sender is allowed to burst, instead this it the maximum time a queue can burst and
    # it's used to limit delay for lower priority queues.
    rt_max_burst_bytes = port_rate_bps * rt_max_burst_s / 8

    # The actual time a sender can burst will be limited by the ingress vs. egress bandwidth and the
    # queue cell reservation, i.e., the maximum queue size (base_use_limit+BAF). To compute queue
    # cell reservations, we distribute the buffer pool between queues (for all ports) proportionally
    # to the queue max shaping rate. This is a consequence of the "bandwidth-delay product", a rule
    # of thumb for sizing buffers, where the bandwidth in our case is the queue max shaping rate. We
    # do this to improve the performance of TCP-like congestion control protocols. While we cannot
    # claim optimal sizing to achieve maximum throughput (we would need to know the average RTT and
    # number of flows), setting higher base_use_limit for queues with higher speeds helps to achieve
    # that goal.
    rt_queue_count = len(rt_max_rates_bps)
    rt_pool_size = pool_sizes[RT_APP_POOL]
    rt_base_use_limits = [
        floor(rt_pool_size * x / sum(rt_max_rates_bps * port_count))
        for x in rt_max_rates_bps
    ]

    # Minimize worst case latency by enforcing fair queueing, i.e., same weight for all slices. We
    # assume the ideal case where all slices send medium size packets (half the MTU). With larger
    # packets, the scheduler accounts for credit deficit.
    rt_wrr_weight = floor(DEFAULT_MTU_BYTES / 2)

    # We do not allow oversubscription. Check that we have enough bandwidth to allocate all slices.
    rt_link_util = sum(rt_max_rates_bps) / port_rate_bps
    rt_avail_bw_bps = (1 - ct_util) * port_rate_bps
    assert sum(rt_max_rates_bps) < rt_avail_bw_bps, (
        "Not enough bandwidth to allocate Real-Time slices: "
        f"requested={format_bps(sum(rt_max_rates_bps))}, "
        f"available={format_bps(ct_util * port_rate_bps)}"
    )

    next_queue_id = FIRST_QUEUE_ID
    for i in range(rt_queue_count):
        descr = f"{rt_slice_names[i]} Real-Time"
        if i == rt_queue_count - 1:
            queue_id = QUEUE_ID_SYSTEM
        else:
            queue_id = next_queue_id
            next_queue_id += 1
        params = dict(
            descr=f"{descr} ({format_bps(rt_max_rates_bps[i])})",
            queue_id=queue_id,
            app_pool=RT_APP_POOL,
            prio=RT_PRIORITY,
            weight=rt_wrr_weight,
            base_use_limit=rt_base_use_limits[i],
            baf=DEFAULT_BAF_PERC,
            pool_size=pool_sizes[RT_APP_POOL],
            max_rate_bps=rt_max_rates_bps[i],
            max_burst_bytes=rt_max_burst_bytes,
            port_rate_bps=port_rate_bps,
        )
        queue_mappings[queue_id] = queue_mapping(**params)
        all_params[rt_slice_names[i]]["realtime"] = params
        used_pool_buls[RT_APP_POOL] += rt_base_use_limits[i]

    # -- ELASTIC
    # Each slice requesting Elastic service gets a dedicated queue, dimensioned to guarantee the
    # given minimum rate during congestion, but allowed to grow when higher priority queues are
    # unused. Best-Effort is treated as an Elastic queues, but uses a different pool.
    el_min_rates_bps = el_min_rates_bps.copy()
    el_slice_names = el_slice_names.copy()
    el_min_rates_bps.append(BE_MIN_RATE_BPS)
    el_slice_names.append(DEFAULT_SLICE_NAME)

    # Compute WRR scheduling weights to distribute the available bandwidth.
    el_norm_weights = [x / sum(el_min_rates_bps) for x in el_min_rates_bps]
    el_wrr_weights = [ceil(1023 * x) for x in el_norm_weights]

    # As before, set base_use_limit proportionally to the queue maximum rate. In this case, the
    # queue maximum rate is not enforced through shaping (hence it is not the same for all ports),
    # but it is proportional to the link bandwidth (port rate).
    el_pool_size = pool_sizes[EL_APP_POOL]
    port_factor = port_rate_bps / sum(port_rates_bps)
    el_rate_factors = [x / sum(el_min_rates_bps[:-1]) for x in el_min_rates_bps[:-1]]
    el_base_use_limits = [
        floor(el_pool_size * port_factor * x) for x in el_rate_factors
    ]

    # Do the same for the Best-Effort pool, we have only one BE queue per port.
    be_pool_size = pool_sizes[BE_APP_POOL]
    be_base_use_limit = floor(be_pool_size * port_rate_bps / sum(port_rates_bps))

    # Check oversubscription.
    el_avail_bw_bps = (1 - rt_link_util - ct_util) * port_rate_bps
    assert sum(el_min_rates_bps) <= el_avail_bw_bps, (
        f"Not enough bandwidth to allocate Elastic slices: "
        f"requested={format_bps(sum(el_min_rates_bps))}, "
        f"available={format_bps(el_avail_bw_bps)}"
    )

    el_queue_count = len(el_min_rates_bps)
    for i in range(el_queue_count):
        if i == el_queue_count - 1:
            # Last one is Best-Effort
            descr = "Best-Effort"
            app_pool = BE_APP_POOL
            pool_size = pool_sizes[BE_APP_POOL]
            base_use_limit = be_base_use_limit
            queue_id = QUEUE_ID_BEST_EFFORT
        else:
            descr = f"{el_slice_names[i]} Elastic"
            app_pool = EL_APP_POOL
            pool_size = pool_sizes[EL_APP_POOL]
            base_use_limit = el_base_use_limits[i]
            queue_id = next_queue_id
            next_queue_id += 1
        # We may be able to allocate more gmin than what was requested.
        norm_min_rate_bps = el_norm_weights[i] * el_avail_bw_bps
        params = dict(
            descr=f"{descr} ({el_norm_weights[i]:.1%}, gmin {format_bps(norm_min_rate_bps)})",
            queue_id=queue_id,
            app_pool=app_pool,
            prio=EL_PRIORITY,
            weight=el_wrr_weights[i],
            base_use_limit=base_use_limit,
            baf=DEFAULT_BAF_PERC,
            pool_size=pool_size,
            port_rate_bps=port_rate_bps,
        )
        queue_mappings[queue_id] = queue_mapping(**params)
        params["norm_min_rate_bps"] = floor(norm_min_rate_bps)
        all_params[el_slice_names[i]]["elastic"] = params
        used_pool_buls[app_pool] += base_use_limit

    # Check that we have enough queues.
    used_queues = 1 + rt_queue_count + el_queue_count
    assert used_queues <= port_queue_count, (
        "Not enough queues: "
        f"requested={used_queues}, "
        f"available={port_queue_count}"
    )

    port_field = "sdk_port" if is_sdk_port else "port"

    text = f"""        queue_configs {{
          # {descr} ({format_bps(port_rate_bps)}, {used_queues} queues)
          {port_field}: {port_id}\n{NEW_LINE.join(queue_mappings)}
        }}"""

    return text, all_params


def pool_config(descr, pool, size, enable_color_drop, limit_yellow=0, limit_red=0):
    """
    Returns a pool_config blob with the given parameters.
    :param descr: a description of the pool
    :param pool: pool number (0-3)
    :param size: number of cells allocated to this pool
    :param enable_color_drop: whether to enable color-ware dropping
    :param limit_yellow: number of used cells after which yellow packets will be dropped
    :param limit_red: number of cells after which red packets will be dropped
    :return:
    """
    return f"""        pool_configs {{
          # {descr}
          pool: EGRESS_APP_POOL_{pool}
          pool_size: {size}
          enable_color_drop: {enable_color_drop}
          color_drop_limit_green: {size}
          color_drop_limit_yellow: {limit_yellow}
          color_drop_limit_red: {limit_red}
        }}"""


def port_shaping_config(descr, port_id, rate_bps, burst_bytes):
    """
    Returns a per_port_shaping_configs blob with the given parameters.
    :param descr: port description
    :param rate_bps: SingletonPort ID form Stratum's chassis_config
    :param rate_bps: shaping rate in bps
    :param burst_bytes: burst_size in bytes
    :return:
    """
    return f"""        per_port_shaping_configs {{
          key: {port_id} # {descr}
          value {{
            byte_shaping {{
              rate_bps: {rate_bps} # {format_bps(rate_bps)}
              burst_bytes: {burst_bytes}
            }}
          }}
        }}"""


def netcfg(slice_names_to_ids, queue_params):
    """
    Return the ONOS netcfg blob.
    """
    config = {}
    for slice_name in slice_names_to_ids:
        slice_params = queue_params[slice_name]
        slice_id = slice_names_to_ids[slice_name]
        key = str(slice_id)
        config[key] = {
            "name": slice_name,
            "tcs": {}
        }
        for tc in slice_params:
            tc_conf = slice_params[tc]
            if tc == "control":
                config[key]["tcs"]["CONTROL"] = {
                    "queueId": tc_conf["queue_id"],
                    "maxRateBps": tc_conf["max_rate_bps"],
                }
            elif tc == "realtime":
                config[key]["tcs"]["REAL_TIME"] = {
                    "queueId": tc_conf["queue_id"],
                    "maxRateBps": tc_conf["max_rate_bps"]
                }
            elif tc == "elastic":
                config[key]["tcs"]["ELASTIC"] = {
                    "queueId": tc_conf["queue_id"],
                    "gminRateBps": tc_conf["norm_min_rate_bps"]
                }
            else:
                raise ValueError(f"Invalid TC: {tc}")
        slice_id += 1

    # The best-effort queue config is implicit in ONOS
    del config[str(DEFAULT_SLICE_ID)]["tcs"]["ELASTIC"]
    # Mark system tc
    config[str(DEFAULT_SLICE_ID)]["tcs"]["REAL_TIME"]["isSystemTc"] = True

    config = {
        "apps": {
            "org.stratumproject.fabric-tna": {
                "slicing": {
                    "slices": config
                }
            }
        }
    }

    return json.dumps(config, indent=2)


def vendor_config(shaping_blobs, queue_blobs):
    """
    Returns the Stratum vendor_config block
    """
    return f"""vendor_config {{
  tofino_config {{
    node_id_to_port_shaping_config {{
      key: 1 
      value {{\n{NEW_LINE.join(shaping_blobs)}
      }}
    }}
    node_id_to_qos_config {{
      key: 1
      value {{\n{NEW_LINE.join(queue_blobs)}
      }}
    }}
  }}
}}
"""


def text_config(yaml_config, type):
    """
    Computes and returns a text config blob
    :param yaml_config: yaml QoS config
    :param type: stratum or onos
    """
    # We keep most of the logic the same for both onos and stratum, so we can
    # run the same checks in both cases.

    slice_names = [DEFAULT_SLICE_NAME] + [s["name"] for s in yaml_config["slices"]]
    assert len(slice_names) == len(set(slice_names)),\
        f"Slice names must be unique: f{slice_names}"
    slice_ids = [i for i in range(DEFAULT_SLICE_ID, len(slice_names))]
    slice_names_to_ids = {x[0]: x[1] for x in zip(slice_names, slice_ids)}

    # Parse slices
    ct_slice_names = []
    ct_max_rates_bps = []
    rt_slice_names = []
    rt_max_rates_bps = []
    el_slice_names = []
    el_min_rates_bps = []
    for slice_config in yaml_config["slices"]:
        for tc in slice_config["tcs"]:
            tc_config = slice_config['tcs'][tc]
            if tc == "control":
                ct_slice_names.append(slice_config["name"])
                ct_max_rates_bps.append(tc_config["max_rate_bps"])
            elif tc == "realtime":
                rt_slice_names.append(slice_config["name"])
                rt_max_rates_bps.append(tc_config["max_rate_bps"])
            elif tc == "elastic":
                el_slice_names.append(slice_config["name"])
                el_min_rates_bps.append(tc_config["gmin_rate_bps"])
            else:
                raise ValueError(f"Invalid TC: {tc}")

    # Allocate buffer cells to pools
    max_cells = yaml_config["max_cells"]
    pool_allocations = [
        yaml_config["pool_allocations"]["control"],
        yaml_config["pool_allocations"]["realtime"],
        yaml_config["pool_allocations"]["elastic"],
        yaml_config["pool_allocations"]["besteffort"],
        yaml_config["pool_allocations"]["unassigned"],
    ]
    assert sum(pool_allocations) == 100, (
        f"Invalid total pool allocation percentage: "
        f"expected=100, actual={sum(pool_allocations)}"
    )
    pool_sizes = [floor(x / 100 * max_cells) for x in pool_allocations]

    slicing_template = dict(
        sys_max_rate_bps=yaml_config["system_max_rate_bps"],
        ct_slice_names=ct_slice_names,
        ct_max_rates_bps=ct_max_rates_bps,
        ct_slot_rate_pps=yaml_config["control_slot_rate_pps"],
        ct_slot_burst_pkts=yaml_config["control_slot_burst_pkts"],
        ct_mtu_bytes=yaml_config["control_mtu_bytes"],
        rt_max_rates_bps=rt_max_rates_bps,
        rt_slice_names=rt_slice_names,
        rt_max_burst_s=yaml_config["realtime_max_burst_s"],
        el_min_rates_bps=el_min_rates_bps,
        el_slice_names=el_slice_names,
        pool_sizes=pool_sizes,
    )

    shaping_blobs = []

    port_templates = []
    for port_template in yaml_config["port_templates"]:
        temp = dict(
            descr=port_template["descr"],
            port_rate_bps=port_template["rate_bps"],
            port_queue_count=port_template["queue_count"],
        )
        if "port_ids" in port_template:
            for port_id in port_template["port_ids"]:
                temp["port_id"] = port_id
                temp["is_sdk_port"] = False
                port_templates.append(temp.copy())
                # Shaping can only be applied to front-panel ports,
                # it doesn't make sense to shape internal ports.
                if port_template["is_shaping_enabled"]:
                    shaping_blobs.append(
                        port_shaping_config(
                            descr=port_template["descr"],
                            port_id=port_id,
                            rate_bps=port_template["rate_bps"],
                            burst_bytes=port_template["shaping_burst_bytes"],
                        )
                    )
        if "sdk_port_ids" in port_template:
            for sdk_port_id in port_template["sdk_port_ids"]:
                temp["port_id"] = sdk_port_id
                temp["is_sdk_port"] = True
                port_templates.append(temp.copy())

    queue_blobs = [
        pool_config(
            descr=f"Control ({pool_allocations[CT_APP_POOL]}%)",
            pool=CT_APP_POOL,
            size=pool_sizes[CT_APP_POOL],
            enable_color_drop="false",
        ),
        pool_config(
            descr=f"Real-Time ({pool_allocations[RT_APP_POOL]}%)",
            pool=RT_APP_POOL,
            size=pool_sizes[RT_APP_POOL],
            enable_color_drop="true",
            limit_yellow=floor(0.90 * pool_sizes[RT_APP_POOL]),
            limit_red=floor(0.80 * pool_sizes[RT_APP_POOL]),
        ),
        pool_config(
            descr=f"Elastic ({pool_allocations[EL_APP_POOL]}%)",
            pool=EL_APP_POOL,
            size=pool_sizes[EL_APP_POOL],
            enable_color_drop="true",
            limit_yellow=floor(0.90 * pool_sizes[EL_APP_POOL]),
            limit_red=floor(0.80 * pool_sizes[EL_APP_POOL]),
        ),
        pool_config(
            descr=f"Best-Effort ({pool_allocations[BE_APP_POOL]}%)",
            pool=BE_APP_POOL,
            size=pool_sizes[BE_APP_POOL],
            enable_color_drop="true",
            limit_yellow=floor(0.90 * pool_sizes[BE_APP_POOL]),
            limit_red=floor(0.80 * pool_sizes[BE_APP_POOL]),
        )]

    # Control variable: stores the sum of base_use_limit (bul) reservations for all pools.
    used_pool_buls = [0, 0, 0, 0]

    # Generate the Stratum queue config for each port, use the returned params
    # to generate the corresponding ONOS netcfg. Stratum config is per-device,
    # while the ONOS config is network-level. What is the maximum bandwidth for
    # a given Slice/TC across all network? It depends on the traffic path and
    # ports traversed. We assume a worst-case routing, as such we use the
    # slowest port params to generate the ONOS netcfg.
    bottleneck_queue_params = None
    for port in port_templates:
        text, confs = queue_config(
            **port,
            port_rates_bps=[x["port_rate_bps"] for x in port_templates],
            used_pool_buls=used_pool_buls,
            **slicing_template,
        )
        if port["port_rate_bps"] == yaml_config["network_bottleneck_bps"]:
            bottleneck_queue_params = confs

    assert type != "onos" or bottleneck_queue_params is not None, \
        f"Cannot generate onos config, at least one `port_template` must " \
        f"have `rate_bps` equal to `network_bottleneck_bps`"

    # Check that we have allocated all pool cells using base_use_limits.
    unused_pool_buls = [
        pool_sizes[i] - used_pool_buls[i] for i in range(len(used_pool_buls))
    ]
    assert (
        min(unused_pool_buls) >= 0
    ), f"Too many allocated cells, something is wrong with base_use_limit: {unused_pool_buls}"
    # Account for small rounding errors (since we use floor).
    assert (
        sum(unused_pool_buls) < max_cells * 0.0001
    ), f"Too many unallocated cells, something is wrong with base_use_limit: {unused_pool_buls}"

    if type == "stratum":
        return vendor_config(shaping_blobs, queue_blobs)
    elif type == "onos":
        return netcfg(slice_names_to_ids, bottleneck_queue_params)


def main():
    parser = argparse.ArgumentParser(prog="gen-qos-config.py")
    parser.add_argument("config", help="Path to yaml QoS config file")
    parser.add_argument("-o", "--output", help="output path", default="-")
    parser.add_argument("-t", "--type", help="onos or stratum", required=True)
    args = parser.parse_args()

    yaml_path = args.config
    output_path = args.output
    yaml_config = None
    with open(yaml_path, "r") as stream:
        try:
            yaml_config = yaml.safe_load(stream)
        except yaml.YAMLError as ex:
            print(ex)
            exit(1)

    text = text_config(yaml_config, type=args.type)
    if output_path == "-":
        # std output
        print(text)
    else:
        with open(output_path, "w") as output_file:
            output_file.write(text)


if __name__ == "__main__":
    main()
