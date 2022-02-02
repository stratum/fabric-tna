// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.slicing.cli;

import org.apache.karaf.shell.api.action.Argument;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.onosproject.cli.AbstractShellCommand;
import org.stratumproject.fabric.tna.slicing.api.SlicingService;

/**
 * CLI command to wipe out all classification state.
 */
@Service
@Command(scope = "fabric-tna", name = "classifier-wipe-out",
        description = "Wipe out all classification flows and default TCs")
public class ClassifierWipeOutCommand extends AbstractShellCommand {

    private static final String PLEASE = "please";
    @Argument(name = "please", description = "Confirmation phrase")
    String please = null;

    @Override
    protected void doExecute() {
        if (please == null || !please.equals(PLEASE)) {
            print("I'm afraid I can't do that!\nSay: %s", PLEASE);
            return;
        }

        SlicingService slicingService = getService(SlicingService.class);

        print("Removing all classifier flows");
        slicingService.removeAllClassifierFlows();
        print("Resetting default traffic classes for all slices");
        slicingService.resetDefaultTrafficClassForAllSlices();
    }
}
