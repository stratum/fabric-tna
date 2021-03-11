/*
 * Copyright 2020-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.princeton.conquest;

import org.onosproject.net.DeviceId;

import java.util.Collection;

public interface ConQuestService {

    /**
     * Remove all table entries installed by this app.
     */
    void removeAllEntries();

    /**
     * Install table entries in the dataplane to produce control plane reports when queues exceed a target delay and
     * some flow is occupying too much of the queue.
     *
     * @param minQueueDelay      The queue delay needed for a report to be generated
     * @param minFlowSizeInQueue How many queue bytes a single flow should occupy for a report to be generated
     */
    void addReportTriggerEverywhere(int minQueueDelay, int minFlowSizeInQueue);

    /**
     * Install table entries in the dataplane to produce control plane reports when queues exceed a target depth
     *
     * @param deviceId           The network device where we should add the report trigger
     * @param minQueueDelay      The queue delay needed for a report to be generated
     * @param minFlowSizeInQueue How many queue bytes a single flow should occupy for a report to be generated
     */
    void addReportTrigger(DeviceId deviceId, int minQueueDelay, int minFlowSizeInQueue);

    /**
     * Remove report triggers from the target device.
     *
     * @param deviceId The device from which report triggers should be removed
     */
    void removeReportTriggers(DeviceId deviceId);

    /**
     * Remove report triggers from all devices on the network.
     */
    void removeAllReportTriggers();

    /**
     * Get all ConQuest reports received by the app.
     *
     * @return A collection of received ConQuest reports.
     */
    Collection<ConQuestReport> getReceivedReports();

    /**
     * Clear the ConQuest reports received by the app.
     */
    void clearReceivedReports();
}