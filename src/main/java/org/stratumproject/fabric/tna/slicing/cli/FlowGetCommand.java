// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0
package org.stratumproject.fabric.tna.slicing.cli;

import org.apache.karaf.shell.api.action.Argument;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.onosproject.cli.AbstractShellCommand;
import org.stratumproject.fabric.tna.slicing.api.SliceId;
import org.stratumproject.fabric.tna.slicing.api.SlicingService;
import org.stratumproject.fabric.tna.slicing.api.TrafficClass;

/**
 * CLI command to list classifier flows.
 */
@Service
@Command(scope = "fabric-tna", name = "classifier-flow-get", description = "List classifier flows")
public class FlowGetCommand extends AbstractShellCommand {
    @Argument(index = 0, name = "sliceId",
            description = "Slice ID",
            required = true, multiValued = false)
    @Completion(SliceIdCompleter.class)
    int sliceId;

    @Argument(index = 1, name = "tc",
            description = "Traffic class",
            required = true, multiValued = false)
    @Completion(TrafficClassCompleter.class)
    String tc;

    @Override
    protected void doExecute() {
        SlicingService slicingService = getService(SlicingService.class);
        print(slicingService.getClassifierFlows(SliceId.of(sliceId), TrafficClass.valueOf(tc)).toString());
    }
}
