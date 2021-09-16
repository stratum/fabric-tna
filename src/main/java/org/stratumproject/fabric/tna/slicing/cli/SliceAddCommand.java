// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.slicing.cli;

import org.apache.karaf.shell.api.action.Argument;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.onosproject.cli.AbstractShellCommand;
import org.onosproject.net.slicing.SliceId;
import org.onosproject.net.slicing.SlicingService;

/**
 * Add network slice.
 */
@Service
@Command(scope = "fabric-tna", name = "slice-add", description = "Add network slice")
public class SliceAddCommand extends AbstractShellCommand {
    @Argument(index = 0, name = "sliceId",
            description = "sliceId. Used to identify a slice.",
            required = true, multiValued = false)
    int sliceId;

    @Override
    protected void doExecute() {
        SlicingService slicingService = getService(SlicingService.class);
        boolean result = slicingService.addSlice(SliceId.of(sliceId));
        if (result) {
            print("Slice %s added", sliceId);
        } else {
            print("Failed to add slice %s", sliceId);
        }
    }
}
