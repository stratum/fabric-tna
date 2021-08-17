// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.slicing.cli;

import org.apache.karaf.shell.api.action.Argument;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.onosproject.cli.AbstractShellCommand;
import org.stratumproject.fabric.tna.slicing.api.QueueId;
import org.stratumproject.fabric.tna.slicing.api.SlicingService;
import org.stratumproject.fabric.tna.slicing.api.TrafficClass;

/**
 * Reserve queue for TC.
 */
@Service
@Command(scope = "fabric-tna", name = "queue-reserve", description = "Reserve queue for TC")
public class QueueReserveCommand extends AbstractShellCommand {
    @Argument(index = 0, name = "queueId",
            description = "queueId. Used to identify a slice.",
            required = true, multiValued = false)
    int queueId;

    @Argument(index = 1, name = "tc",
            description = "Traffic class. Used to classify the traffic.",
            required = true, multiValued = false)
    String tc;

    @Override
    protected void doExecute() {
        SlicingService slicingService = getService(SlicingService.class);
        boolean result = slicingService.reserveQueue(QueueId.of(queueId), TrafficClass.valueOf(tc));
        if (result) {
            print("Queue %s reserved for TC %s", queueId, tc);
        } else {
            print("Failed to reserve queue %s for TC %s", queueId, tc);
        }
    }
}
