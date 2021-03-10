package org.princeton.p4rtt.cli;

import org.apache.karaf.shell.api.action.Argument;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.onlab.packet.Ip4Address;
import org.onosproject.cli.net.DeviceIdCompleter;
import org.onosproject.net.Device;
import org.onosproject.net.DeviceId;
import org.onosproject.net.device.DeviceService;
import org.princeton.p4rtt.ConQuestService;
import org.onosproject.cli.AbstractShellCommand;

/**
 * P4RTT command to monitor a given (src,dst) flow.
 */
@Service
@Command(scope = "conquest", name = "add-report-trigger",
        description = "Begin recording P4RTT statistics for the given (src,dst) flow.")
public class AddReportTriggerCommand extends AbstractShellCommand {
    @Argument(index = 0, name = "queue-depth",
            description = "The minimum queue depth needed to trigger reports",
            required = true)
    String queueDepth = null;

    @Argument(index = 1, name = "ipv4-dst",
            description = "Destination IP of the flow for which to grab P4RTT stats",
            required = true)
    String ipv4Dst = null;


    @Argument(index = 2, name = "uri",
            description = "Device ID. If not provided, the flow will be monitored on all available devices",
            required = false, multiValued = false)
    @Completion(DeviceIdCompleter.class)
    String uri = null;

    @Override
    protected void doExecute() {
        ConQuestService app = get(ConQuestService.class);

        Ip4Address srcAddr = Ip4Address.valueOf(ipv4Src);
        Ip4Address dstAddr = Ip4Address.valueOf(ipv4Dst);

        if (uri != null) {
            DeviceService deviceService = get(DeviceService.class);
            Device device = deviceService.getDevice(DeviceId.deviceId(uri));
            if (device == null) {
                print("Device \"%s\" is not found", uri);
                return;
            }
            app.monitorFlow(device.id(), srcAddr, dstAddr);
            print("Installed monitoring for flow (%s, %s) on device %s.", srcAddr, dstAddr, device.id());
        } else {
            app.monitorFlowEverywhere(srcAddr, dstAddr);
            print("Installed monitoring for flow (%s, %s) on all devices.", srcAddr, dstAddr);
        }
    }

}
