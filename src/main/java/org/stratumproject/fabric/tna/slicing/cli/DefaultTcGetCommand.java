// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0
package org.stratumproject.fabric.tna.slicing.cli;

import org.apache.karaf.shell.api.action.Argument;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.onosproject.cli.AbstractShellCommand;
import org.stratumproject.fabric.tna.slicing.api.SliceId;
import org.stratumproject.fabric.tna.slicing.api.SlicingService;

/**
 * Get default traffic class of a slice.
 */
@Service
@Command(scope = "fabric-tna", name = "default-tc-get", description = "Get default traffic class of a slice")
public class DefaultTcGetCommand extends AbstractShellCommand {
    @Argument(index = 0, name = "sliceId",
            description = "sliceId. Used to identify a slice.",
            required = true, multiValued = false)
    int sliceId;

    @Override
    protected void doExecute() {
        SlicingService slicingService = getService(SlicingService.class);
        print(slicingService.getDefaultTrafficClass(SliceId.of(sliceId)).toString());
    }
}
