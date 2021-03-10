package org.princeton.p4rtt.cli;

import org.apache.karaf.shell.api.action.Argument;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.onosproject.net.device.DeviceService;
import org.princeton.p4rtt.ConQuestService;
import org.onosproject.cli.AbstractShellCommand;
import org.princeton.p4rtt.ConQuestReport;

import java.util.ArrayList;

/**
 * P4RTT top N command
 */
@Service
@Command(scope = "p4rtt", name = "top-n",
        description = "Grab the top N slowest flows seen")
public class TopNCommand extends AbstractShellCommand {
    @Argument(index = 0, name = "n",
            description = "How many reports to grab",
            required = true)
    int n = 0;

    @Argument(index = 1, name = "threshold",
            description = "The minimum RTT we are interested in",
            required = false)
    int threshold = 0;

    @Override
    protected void doExecute() {
        DeviceService deviceService = get(DeviceService.class);
        ConQuestService app = get(ConQuestService.class);

        ArrayList<ConQuestReport> topReports =  app.topNRttFlows(n, threshold);

        print("-- Top %d Flow Reports --", n);
        int i = 0;
        for (ConQuestReport report : topReports) {
            print("%d): %s", i, report.toVerboseString());
            i++;
        }
        print("-- End Flow Reports --");

    }

}
