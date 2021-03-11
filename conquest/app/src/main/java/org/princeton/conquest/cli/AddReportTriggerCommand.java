package org.princeton.conquest.cli;

import org.apache.karaf.shell.api.action.Argument;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.onlab.packet.Ip4Address;
import org.onosproject.cli.net.DeviceIdCompleter;
import org.onosproject.net.Device;
import org.onosproject.net.DeviceId;
import org.onosproject.net.device.DeviceService;
import org.princeton.conquest.ConQuestService;
import org.onosproject.cli.AbstractShellCommand;

/**
 * ConQuest command to add report triggers to the dataplane.
 */
@Service
@Command(scope = "conquest", name = "add-report-trigger",
        description = "Add report triggers to the dataplane.")
public class AddReportTriggerCommand extends AbstractShellCommand {
    @Argument(index = 0, name = "queue-delay",
            description = "The minimum queue delay needed to trigger reports",
            required = true)
    int queueDepth = 0;

    @Argument(index = 1, name = "flow-size-in-queue",
            description = "The size of a flow in a queue that will trigger a report",
            required = true)
    int flowSize = 0;


    @Argument(index = 2, name = "uri",
            description = "Device ID. If not provided, report triggers will be added to all available devices",
            required = false, multiValued = false)
    @Completion(DeviceIdCompleter.class)
    String uri = null;

    @Override
    protected void doExecute() {
        ConQuestService app = get(ConQuestService.class);

        if (uri != null) {
            DeviceService deviceService = get(DeviceService.class);
            Device device = deviceService.getDevice(DeviceId.deviceId(uri));
            if (device == null) {
                print("Device \"%s\" is not found", uri);
                return;
            }
            app.addReportTrigger(device.id(), queueDepth, flowSize);
            print("Installed report triggers on device %s.", device.id());
        } else {
            app.addReportTriggerEverywhere(queueDepth, flowSize);
            print("Installed report triggers on all devices.");
        }
    }

}
