package org.princeton.conquest.cli;

import org.apache.karaf.shell.api.action.Argument;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.onosproject.cli.AbstractShellCommand;
import org.onosproject.cli.net.DeviceIdCompleter;
import org.onosproject.net.Device;
import org.onosproject.net.DeviceId;
import org.onosproject.net.device.DeviceService;
import org.princeton.conquest.ConQuestService;

/**
 * ConQuest command to clear report triggers.
 */
@Service
@Command(scope = "conquest", name = "clear-triggers",
        description = "Clear all ConQuest report triggers from the dataplane")
public class ClearReportTriggerCommand extends AbstractShellCommand {
    @Argument(index = 0, name = "uri",
            description = "Device ID. If not provided, report triggers will be cleared from all available devices",
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
            app.removeReportTriggers(device.id());
            print("Added report triggers to device %s.", device.id());
        } else {
            app.removeAllReportTriggers();
            print("Removed report triggers from all devices.");
        }
    }

}
