package org.princeton.p4rtt.cli;

import org.apache.karaf.shell.api.action.Argument;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.onlab.packet.Ip4Address;
import org.onosproject.net.device.DeviceService;
import org.princeton.p4rtt.ConQuestService;
import org.onosproject.cli.AbstractShellCommand;

/**
 * Example P4RTT Command. Not done.
 */
@Service
@Command(scope = "p4rtt", name = "get-stats",
        description = "Grab P4RTT statistics for the given (src,dst) flow.")
public class P4RttStatsCommand extends AbstractShellCommand {
    @Argument(index = 0, name = "ipv4-src",
            description = "Source IP of the flow for which to grab P4RTT stats",
            required = true)
    String ipv4Src = null;

    @Argument(index = 1, name = "ipv4-dst",
            description = "Destination IP of the flow for which to grab P4RTT stats",
            required = true)
    String ipv4Dst = null;

    @Override
    protected void doExecute() {
        DeviceService deviceService = get(DeviceService.class);
        ConQuestService app = get(ConQuestService.class);

        Ip4Address srcAddr = Ip4Address.valueOf(ipv4Src);
        Ip4Address dstAddr = Ip4Address.valueOf(ipv4Dst);

        print("Grabbing statistics for flow (%s, %s)...", srcAddr, dstAddr);
        // FIXME: add deviceId to getStatistics() signature
        int stats = app.getStatistics(srcAddr, dstAddr);
        if (stats == -1) {
            print("No statistics found!");
        } else {
            print("Statistics: %s", stats);
        }
    }

}
