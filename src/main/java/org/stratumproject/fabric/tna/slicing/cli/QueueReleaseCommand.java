// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.slicing.cli;

import org.apache.karaf.shell.api.action.Argument;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.onosproject.cli.AbstractShellCommand;
import org.stratumproject.fabric.tna.slicing.api.QueueId;
import org.stratumproject.fabric.tna.slicing.api.SlicingAdminService;
/**
 * Reserve queue for TC.
 */
@Service
@Command(scope = "fabric-tna", name = "queue-release", description = "Release queue from TC")
public class QueueReleaseCommand extends AbstractShellCommand {
    @Argument(index = 0, name = "queueId",
            description = "queueId. Used to identify a queue.",
            required = true, multiValued = false)
    int queueId;

    @Override
    protected void doExecute() {
        SlicingAdminService slicingAdminService = getService(SlicingAdminService.class);
        boolean result = slicingAdminService.releaseQueue(QueueId.of(queueId));
        if (result) {
            print("Queue %s released", queueId);
        } else {
            print("Failed to release queue %s", queueId);
        }
    }
}
