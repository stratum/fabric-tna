// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.slicing.cli;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.onosproject.net.flow.TrafficSelector;
import org.stratumproject.fabric.tna.slicing.api.SliceId;
import org.stratumproject.fabric.tna.slicing.api.SlicingService;
import org.stratumproject.fabric.tna.slicing.api.TrafficClass;

/**
 * CLI command to remove classifier flows.
 */
@Service
@Command(scope = "fabric-tna", name = "classifier-flow-remove", description = "Remove a classifier flow")
public class FlowRemoveCommand extends AbstractFlowCommand {

    @Override
    protected void doExecute() {
        SlicingService slicingService = getService(SlicingService.class);
        TrafficSelector selector = parseSelector();

        if (slicingService.removeClassifierFlow(selector, SliceId.of(sliceId), TrafficClass.valueOf(tc))) {
            print("Flow %s removed from slice %d tc %s", selector.toString(), sliceId, tc);
        }
    }
}
