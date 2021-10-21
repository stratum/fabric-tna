// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package org.stratumproject.fabric.tna.inbandtelemetry;

import java.util.Collections;
import java.util.List;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.google.common.collect.Lists;

import org.onlab.packet.IpAddress;
import org.onlab.packet.IpPrefix;
import org.onlab.packet.TpPort;
import org.onosproject.core.ApplicationId;
import org.onosproject.net.config.Config;
import org.onosproject.ui.JsonUtils;

/**
 * Configuration for INT report and watchlist. Config example:
 * {
 *   "apps": {
 *     "org.stratumproject.fabric.tna.inbandtelemetry": {
 *       "report": {
 *         "collectorIp": "192.168.0.1",
 *         "collectorPort": 5500,
 *         "minFlowHopLatencyChangeNs": 300,
 *         "watchSubnets": [ "192.168.0.0/24", "10.140.0.0/16" ],
 *         "queueReportLatencyThresholds": {
 *             "0": {"triggerNs": 2000, "resetNs": 1500},
 *             "7": {"triggerNs": 500}
 *         }
 *       }
 *     }
 *   }
 * }
 */
public class IntReportConfig extends Config<ApplicationId> {
    private static final String COLLECTOR_IP = "collectorIp";
    private static final String COLLECTOR_PORT = "collectorPort";
    private static final String MIN_FLOW_HOP_LATENCY_CHANGE_NS = "minFlowHopLatencyChangeNs";
    private static final String WATCH_SUBNETS = "watchSubnets";
    private static final String QUEUE_REPORT_LATENCY_THRESHOLDS = "queueReportLatencyThresholds";
    private static final String TRIGGER_NS = "triggerNs";
    private static final String RESET_NS = "resetNs";
    private static final long DEFAULT_QUEUE_REPORT_TRIGGER_LATENCY_THRESHOLD = 0xffffffffL; // do not report.
    private static final long DEFAULT_QUEUE_REPORT_RESET_LATENCY_THRESHOLD = 0; // do not reset.
    private static final int DEFAULT_MIN_FLOW_HOP_LATENCY_CHANGE_NS = 256;

    /**
     * IP address of the collector. This is the destination IP address that will be
     * used for all INT reports generated by all INT devices.
     *
     * @return collector IP address, null if not present
     */
    public IpAddress collectorIp() {
        if (object.hasNonNull(COLLECTOR_IP)) {
            return IpAddress.valueOf(JsonUtils.string(object, COLLECTOR_IP));
        } else {
            return null;
        }
    }

    /**
     * UDP port number of the collector. This is the destination UDP port number
     * that will be used for all INT reports generated by all INT devices.
     *
     * @return collector UDP port number, null if not present
     */
    public TpPort collectorPort() {
        if (object.hasNonNull(COLLECTOR_PORT)) {
            return TpPort.tpPort((int) JsonUtils.number(object, COLLECTOR_PORT));
        } else {
            return null;
        }
    }

    /**
     * Gets the minimal interval of hop latency change for a flow. This value is
     * used to instruct an INT-capable device to produce reports only for packets
     * which hop latency changed by at least minFlowHopLatencyChangeNs from the
     * previously reported value for the same flow (5-tuple), i.e., produce a report
     * only if `(currentHopLatency - previousHopLatency) &gt;
     * minFlowHopLatencyChangeNs`. Some device implementations might support only
     * specific intervals, e.g., powers of 2.
     *
     * @return Interval in nanoseconds
     */
    public int minFlowHopLatencyChangeNs() {
        if (object.hasNonNull(MIN_FLOW_HOP_LATENCY_CHANGE_NS)) {
            return (int) JsonUtils.number(object, MIN_FLOW_HOP_LATENCY_CHANGE_NS);
        } else {
            return DEFAULT_MIN_FLOW_HOP_LATENCY_CHANGE_NS;
        }
    }

    /**
     * Gets subnets to be watched.
     *
     * @return subnets to be watched
     */
    public List<IpPrefix> watchSubnets() {
        if (object.hasNonNull(WATCH_SUBNETS) && object.path(WATCH_SUBNETS).isArray()) {
            List<IpPrefix> subnets = Lists.newArrayList();
            ArrayNode subnetArray = (ArrayNode) object.path(WATCH_SUBNETS);
            subnetArray.forEach(subnetNode -> {
                subnets.add(IpPrefix.valueOf(subnetNode.asText()));
            });
            return subnets;
        } else {
            return Collections.emptyList();
        }
    }

    /**
     * Gets the latency threshold for a queue that triggers the device to send a queue report.
     *
     * @param queueId the queue id
     * @return latency threshold in nanoseconds
     */
    public long queueReportTriggerLatencyThresholdNs(byte queueId) {
        String queueIdStr = String.valueOf(queueId);
        if (object.hasNonNull(QUEUE_REPORT_LATENCY_THRESHOLDS)) {
            ObjectNode thresholds = JsonUtils.node(object, QUEUE_REPORT_LATENCY_THRESHOLDS);
            if (thresholds.hasNonNull(queueIdStr)) {
                ObjectNode threshold = JsonUtils.node(thresholds, queueIdStr);
                if (threshold.hasNonNull(TRIGGER_NS)) {
                    return (long) JsonUtils.number(threshold, TRIGGER_NS);
                } else {
                    return DEFAULT_QUEUE_REPORT_TRIGGER_LATENCY_THRESHOLD;
                }
            } else {
                return DEFAULT_QUEUE_REPORT_TRIGGER_LATENCY_THRESHOLD;
            }
        } else {
            return DEFAULT_QUEUE_REPORT_TRIGGER_LATENCY_THRESHOLD;
        }
    }

    /**
     * Gets the latency threshold for a queue that resets the queue report quota.
     * If "resetNs" is not present for spefic queue, but the "triggerNs" is, then the value
     * will be "triggerNs / 2".
     *
     * @param queueId the queue id
     * @return latency threshold in nanoseconds
     */
    public long queueReportResetLatencyThresholdNs(byte queueId) {
        String queueIdStr = String.valueOf(queueId);
        if (object.hasNonNull(QUEUE_REPORT_LATENCY_THRESHOLDS)) {
            ObjectNode thresholds = JsonUtils.node(object, QUEUE_REPORT_LATENCY_THRESHOLDS);
            if (thresholds.hasNonNull(queueIdStr)) {
                ObjectNode threshold = JsonUtils.node(thresholds, queueIdStr);
                if (threshold.hasNonNull(RESET_NS)) {
                    return (long) JsonUtils.number(threshold, RESET_NS);
                } else if (threshold.hasNonNull(TRIGGER_NS)) {
                    return queueReportTriggerLatencyThresholdNs(queueId) / 2;
                } else {
                    // Both tiggerNs and resetNs are not present.
                    return DEFAULT_QUEUE_REPORT_RESET_LATENCY_THRESHOLD;
                }
            } else {
                return DEFAULT_QUEUE_REPORT_RESET_LATENCY_THRESHOLD;
            }
        } else {
            return DEFAULT_QUEUE_REPORT_RESET_LATENCY_THRESHOLD;
        }
    }
}
