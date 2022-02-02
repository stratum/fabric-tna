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
 * CLI command to add classifier flows.
 */
@Service
@Command(scope = "fabric-tna", name = "classifier-flow-add", description = "Add a classifier flow")
public class FlowAddCommand extends AbstractFlowCommand {

    @Override
    protected void doExecute() {
        SlicingService slicingService = getService(SlicingService.class);
        TrafficSelector selector = parseSelector();

        if (slicingService.addClassifierFlow(selector, SliceId.of(sliceId), TrafficClass.valueOf(tc))) {
            print("Flow %s added to slice %d tc %s", selector.toString(), sliceId, tc);
        }
    }
}
