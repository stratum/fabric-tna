// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.stats.cli;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.onosproject.cli.AbstractShellCommand;
import org.stratumproject.fabric.tna.stats.StatisticKey;
import org.stratumproject.fabric.tna.stats.StatisticService;

import java.util.Comparator;

/**
 * Lists fabric-tna statistics.
 */
@Service
@Command(scope = "fabric-tna", name = "stats", description = "List statistics table entries")

public class StatListCommand extends AbstractShellCommand {
    @Override
    protected void doExecute() {
        StatisticService statisticService = get(StatisticService.class);
        statisticService.getMonitors().stream()
                .sorted(Comparator.comparingInt(StatisticKey::id))
                .forEach(key -> {
                    print("%5d: %s", key.id(), key.selector());
                });
    }
}
