// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.slicing.cli;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.onosproject.cli.AbstractShellCommand;
import org.stratumproject.fabric.tna.slicing.api.SlicingService;

/**
 * Get network slices.
 */
@Service
@Command(scope = "slicing", name = "slices", description = "Get network slices")
public class SliceGetCommand extends AbstractShellCommand {

    @Override
    protected void doExecute() {
        SlicingService slicingService = getService(SlicingService.class);
        print(slicingService.getSlices().toString());
    }
}
