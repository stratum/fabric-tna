// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0
package org.stratumproject.fabric.tna.stats.cli;

import org.apache.karaf.shell.api.action.Argument;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.onosproject.cli.AbstractShellCommand;
import org.onosproject.net.flow.TrafficSelector;
import org.stratumproject.fabric.tna.stats.StatisticService;

/**
 * Remove fabric-tna statistics.
 */
@Service
@Command(scope = "fabric-tna", name = "stat-remove", description = "Remove statistics table entries")

public class StatRemoveCommand extends AbstractShellCommand {
    @Argument(index = 0, name = "id",
            description = "id",
            required = true, multiValued = false)
    int id;

    @Option(name = "-si", aliases = "--srcIp",
            description = "source IP (e.g. 192.168.1.1)",
            required = false, multiValued = false)
    String srcIp = null;

    @Option(name = "-sp", aliases = "--srcPort",
            description = "source port (e.g. 80)",
            required = false, multiValued = false)
    short srcPort = 0;

    @Option(name = "-di", aliases = "--dstIp",
            description = "destination IP (e.g. 192.168.2.1)",
            required = false, multiValued = false)
    String dstIp = null;

    @Option(name = "-dp", aliases = "--dstPort",
            description = "destination port (e.g. 443)",
            required = false, multiValued = false)
    short dstPort = 0;

    @Option(name = "-p", aliases = "--proto",
            description = "IP protocol (TCP/UDP/ICMP)",
            required = false, multiValued = false)
    String proto = null;

    @Override
    protected void doExecute() {
        TrafficSelector selector = Utils.buildTrafficSelector(srcIp, dstIp, proto, srcPort, dstPort);

        StatisticService statisticService = getService(StatisticService.class);
        statisticService.removeMonitor(selector, id);
    }
}
