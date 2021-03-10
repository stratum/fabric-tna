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
package org.princeton.p4rtt;

import org.onosproject.net.DeviceId;
import org.onosproject.net.flow.criteria.PiCriterion;
import org.onosproject.net.pi.model.PiTableId;
import org.onlab.packet.Ip4Address;

import java.util.ArrayList;

public interface ConQuestService {

    /**
     * Remove Some entry from the P4RTT pipeline.
     * @param match match conditions of the entry to remove
     * @param tableId ID of the table that contains the entry
     */
    void removeSomeEntry(PiCriterion match, PiTableId tableId);

    /**
     * Remove all table entries installed by this app.
     */
    void removeAllEntries();

    /**
     * Install table entries in the dataplane to produce control plane reports when queues exceed a target depth
     * @param queueDepth The queue depth needed for a report to be generated
     */
    void addReportTriggerEverywhere(int queueDepth);

    /**
     * Install table entries in the dataplane to produce control plane reports when queues exceed a target depth
     * @param deviceId The network device where we should add the report trigger
     * @param queueDepth The queue depth needed for a report to be generated
     */
    void addReportTrigger(DeviceId deviceId, int queueDepth);

    /**
     * Get statistics (average) for the given (src,dst) flow.
     *  If nothing for (src,dst), return -1.
     *
     * @param srcAddr source IPV4 address of the flow.
     * @param dstAddr destination IPV4 address of the flow.
     * @return Average RTT or something for the flow. If no entry for (src,dst), return -1.
     */
    int getStatistics(Ip4Address srcAddr, Ip4Address dstAddr);

    /**
     *
     * Get Top N flows that have the highest RTTs
     *
     * @param n Top N flows
     * @param threshold threshold in milliseconds
     * @return Array of top flows with highest average RTTs over threshold.
     */
    ArrayList<ConQuestReport> topNRttFlows(int n, int threshold);
}