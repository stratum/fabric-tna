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
 * Remove traffic class.
 */
@Service
@Command(scope = "fabric-tna", name = "tc-remove", description = "Remove traffic class")
public class TcRemoveCommand extends AbstractShellCommand {
    @Argument(index = 0, name = "sliceId",
            description = "sliceId. Used to identify a slice.",
            required = true, multiValued = false)
    int sliceId;

    @Argument(index = 1, name = "tc",
            description = "Traffic class. Used to classify the traffic.",
            required = true, multiValued = false)
    String tc;

    @Override
    protected void doExecute() {
        SlicingService slicingService = getService(SlicingService.class);
        slicingService.removeTrafficClass(SliceId.of(sliceId), TrafficClass.valueOf(tc));
    }
}
