// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.slicing.cli;

import org.apache.karaf.shell.api.action.Argument;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.onosproject.cli.AbstractShellCommand;
import org.stratumproject.fabric.tna.slicing.api.SliceId;
import org.stratumproject.fabric.tna.slicing.api.SlicingService;
import org.stratumproject.fabric.tna.slicing.api.TrafficClass;

/**
 * Get flows from slice.
 */
@Service
@Command(scope = "fabric-tna", name = "classifier-flow-get", description = "Get classifier flow by slice id and tc")
public class FlowGetCommand extends AbstractShellCommand {
    @Argument(index = 0, name = "sliceId",
            description = "SliceId (0 - 15)",
            required = true, multiValued = false)
    int sliceId;

    @Argument(index = 1, name = "tc",
            description = "Traffic class. Used to classify the traffic." +
                " Possible values: BEST_EFFORT, CONTROL, REAL_TIME, ELASTIC",
            required = true, multiValued = false)
    String tc;

    @Override
    protected void doExecute() {
        SlicingService slicingService = getService(SlicingService.class);
        print(slicingService.getClassifierFlows(SliceId.of(sliceId), TrafficClass.valueOf(tc)).toString());
    }
}
