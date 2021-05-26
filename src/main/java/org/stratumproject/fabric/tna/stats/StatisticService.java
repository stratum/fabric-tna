// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package org.stratumproject.fabric.tna.stats;

import org.onosproject.net.flow.TrafficSelector;

import java.util.Map;
import java.util.Set;

public interface StatisticService {
    /**
     * Add a new monitor rule to both ingress and egress stats table.
     *
     * @param selector criteria to be monitored
     * @param id id. Also used as priority of the monitor flow
     */
    void addMonitor(TrafficSelector selector, int id);

    /**
     * Remove both ingress and egress stats table.
     *
     * @param selector criteria to be removed
     * @param id id. Also used as priority of the monitor flow
     */
    // TODO Make id unique so we can remove solely based on id
    void removeMonitor(TrafficSelector selector, int id);

    /**
     * Gets current flows being monitored.
     *
     * @return set of StatisticKey
     */
    Set<StatisticKey> getMonitors();

    /**
     * Gets statistics of given StatisticKey.
     *
     * @param id id
     * @return map of StatisticDataKey to StatisticDataValue, null if not found
     */
    Map<StatisticDataKey, StatisticDataValue> getStats(int id);
}
