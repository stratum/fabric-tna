// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.stats.cli;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.onosproject.cli.AbstractShellCommand;
import org.stratumproject.fabric.tna.stats.HighlightKey;
import org.stratumproject.fabric.tna.stats.HighlightService;

import java.util.Comparator;

/**
 * Lists fabric-tna highlights.
 */
@Service
@Command(scope = "fabric-tna", name = "highlights", description = "List highlights")

public class HighlightListCommand extends AbstractShellCommand {
    @Override
    protected void doExecute() {
        HighlightService highlightService = getService(HighlightService.class);
        highlightService.getHighlights().stream()
                .sorted(Comparator.comparingInt(HighlightKey::id))
                .forEach(key -> {
                    print("%5d %10s: %s", key.id(), key.name(), key.mod());
                });
    }
}
