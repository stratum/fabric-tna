package org.princeton.p4rtt.cli;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.princeton.p4rtt.ConQuestService;
import org.onosproject.cli.AbstractShellCommand;

/**
 * P4RTT command to clear table entries.
 */
@Service
@Command(scope = "p4rtt", name = "clear-monitoring",
        description = "Clear all monitoring table entries installed by P4RTT")
public class ClearMonitoringCommand extends AbstractShellCommand {

    @Override
    protected void doExecute() {
        ConQuestService app = get(ConQuestService.class);

        app.removeAllEntries();
        print("All monitoring entries removed.");
    }

}
