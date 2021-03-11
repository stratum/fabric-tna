package org.princeton.conquest.cli;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.onosproject.cli.AbstractShellCommand;
import org.princeton.conquest.ConQuestService;

/**
 * ConQuest clear reports command.
 */
@Service
@Command(scope = "conquest", name = "clear-reports",
        description = "Clear all received reports")
public class ClearReportsCommand extends AbstractShellCommand {
    @Override
    protected void doExecute() {
        ConQuestService app = get(ConQuestService.class);

        app.clearReceivedReports();
        print("Cleared reports");
    }
}
