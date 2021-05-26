// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.stats.cli;

import org.apache.karaf.shell.api.action.Argument;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.onosproject.cli.AbstractShellCommand;
import org.onosproject.ui.topo.Mod;
import org.stratumproject.fabric.tna.stats.HighlightService;

/**
 * Add topology highlight.
 */
@Service
@Command(scope = "fabric-tna", name = "highlight-add", description = "Add topology highlight")

public class HighlightAddCommand extends AbstractShellCommand {
    @Argument(index = 0, name = "id",
            description = "id. Used to associate with monitor in StatisticService.",
            required = true, multiValued = false)
    int id;

    @Argument(index = 1, name = "name",
            description = "name (e.g. user1)",
            required = true, multiValued = false)
    String name;

    @Argument(index = 2, name = "mod",
            description = "style of the highlight " +
                    "(e.g. style=\\\"stroke: #ff0000; stroke-width: 4px; stroke-dasharray: 4 2;\\\"",
            required = true, multiValued = false)
    String modStr;

    @Override
    protected void doExecute() {
        HighlightService highlightService = getService(HighlightService.class);
        highlightService.addHighlight(id, name,  new Mod(modStr));
    }
}
