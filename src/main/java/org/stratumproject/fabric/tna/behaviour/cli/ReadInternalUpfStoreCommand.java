// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.behaviour.cli;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.onosproject.cli.AbstractShellCommand;
import org.stratumproject.fabric.tna.behaviour.upf.DistributedFabricUpfStore;
import org.stratumproject.fabric.tna.behaviour.upf.FabricUpfStore;
import org.stratumproject.fabric.tna.behaviour.upf.UpfRuleIdentifier;

import java.util.Map;

/**
 * Read internal UPF store of fabric-tna.
 */
@Service
@Command(scope = "fabric-tna", name = "upf-read-internal-store",
        description = "Print internal UPF stores")
public class ReadInternalUpfStoreCommand extends AbstractShellCommand {
    @Option(name = "-v", aliases = "--verbose",
            description = "Print more detail of each entry",
            required = false, multiValued = false)
    private boolean verbose = false;

    @Override
    protected void doExecute() {
        FabricUpfStore upfStore = get(DistributedFabricUpfStore.class);

        if (upfStore == null) {
            print("Error: FabricUpfStore is null");
            return;
        }

        Map<UpfRuleIdentifier, Integer> farIdMap = upfStore.getFarIdMap();
        print("farIdMap size: " + farIdMap.size());
        if (verbose) {
            farIdMap.entrySet().forEach(entry -> print(entry.toString()));
        }
    }
}
