// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package org.stratumproject.fabric.tna.inbandtelemetry;

import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import java.util.concurrent.ExecutorService;

import com.google.common.collect.Streams;

import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.mastership.MastershipService;
import org.onosproject.net.Device;
import org.onosproject.net.config.ConfigFactory;
import org.onosproject.net.config.NetworkConfigEvent;
import org.onosproject.net.config.NetworkConfigListener;
import org.onosproject.net.config.NetworkConfigRegistry;
import org.onosproject.net.config.NetworkConfigService;
import org.onosproject.net.config.basics.SubjectFactories;
import org.onosproject.net.device.DeviceEvent;
import org.onosproject.net.device.DeviceListener;
import org.onosproject.net.device.DeviceService;

import static java.util.concurrent.Executors.newSingleThreadScheduledExecutor;
import static org.slf4j.LoggerFactory.getLogger;
import static org.onlab.util.Tools.groupedThreads;

@Component(immediate = true)
public class IntManager {
    private static final Logger log = getLogger(IntManager.class);
    private static final String APP_NAME = "org.stratumproject.fabric.tna.inbandtelemetry";

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected NetworkConfigService netcfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected NetworkConfigRegistry netcfgRegistry;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected DeviceService deviceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected MastershipService mastershipService;

    private ApplicationId appId;
    private ExecutorService eventExecutor;
    private final NetworkConfigListener intReportConfigListener = new IntReportConfigListener();
    private final DeviceListener deviceListener = new InternalDeviceListener();

    private final ConfigFactory<ApplicationId, IntReportConfig> intAppConfigFactory = new ConfigFactory<>(
            SubjectFactories.APP_SUBJECT_FACTORY, IntReportConfig.class, "report") {
        @Override
        public IntReportConfig createConfig() {
            return new IntReportConfig();
        }
    };

    @Activate
    public void activate() {
        appId = coreService.registerApplication(APP_NAME);
        eventExecutor = newSingleThreadScheduledExecutor(groupedThreads("onos/int", "events-%d", log));
        netcfgRegistry.registerConfigFactory(intAppConfigFactory);
        netcfgService.addListener(intReportConfigListener);
        deviceService.addListener(deviceListener);
        Streams.stream(deviceService.getAvailableDevices()).forEach(this::initDevice);
        IntReportConfig config = netcfgService.getConfig(appId, IntReportConfig.class);
        Streams.stream(deviceService.getAvailableDevices()).forEach(device -> setUpIntConfig(config, device));
        log.info("Started");
    }

    @Deactivate
    public void deactivate() {
        netcfgService.removeListener(intReportConfigListener);
        deviceService.removeListener(deviceListener);
        eventExecutor.shutdown();
        netcfgRegistry.unregisterConfigFactory(intAppConfigFactory);
        Streams.stream(deviceService.getAvailableDevices()).forEach(this::cleanupDevice);
        log.info("Stopped");
    }

    private boolean isIntProgrammable(Device device) {
        return device != null && device.is(IntProgrammable.class);
    }

    private void initDevice(Device device) {
        if (device != null && isIntProgrammable(device) && mastershipService.isLocalMaster(device.id())) {
            device.as(IntProgrammable.class).init();
        }
    }

    private void cleanupDevice(Device device) {
        if (device != null && isIntProgrammable(device) && mastershipService.isLocalMaster(device.id())) {
            device.as(IntProgrammable.class).cleanup();
        }
    }

    private void setUpIntConfig(IntReportConfig config, Device device) {
        if (isIntProgrammable(device) && mastershipService.isLocalMaster(device.id())
                && !device.as(IntProgrammable.class).setUpIntConfig(config)) {
            log.warn("Failed to set up INT report config for device {}", device.id());
        }
    }

    private class IntReportConfigListener implements NetworkConfigListener {
        @Override
        public void event(NetworkConfigEvent event) {
            eventExecutor.execute(() -> {
                switch (event.type()) {
                    case CONFIG_ADDED:
                    case CONFIG_UPDATED:
                        event.config().map(IntReportConfig.class::cast).ifPresent(config -> {
                            Streams.stream(deviceService.getAvailableDevices())
                                    .forEach(device -> setUpIntConfig(config, device));
                        });
                        break;
                    // TODO: Support removing INT config.
                    default:
                        break;
                }
            });
        }

        @Override
        public boolean isRelevant(NetworkConfigEvent event) {
            return event.configClass() == IntReportConfig.class;
        }
    }

    private class InternalDeviceListener implements DeviceListener {
        @Override
        public void event(DeviceEvent event) {
            eventExecutor.execute(() -> {
                switch (event.type()) {
                    case DEVICE_ADDED:
                    case DEVICE_UPDATED:
                    case DEVICE_AVAILABILITY_CHANGED:
                        IntReportConfig config = netcfgService.getConfig(appId, IntReportConfig.class);
                        if (config != null) {
                            Device device = event.subject();
                            initDevice(device);
                            setUpIntConfig(config, device);
                        }
                        break;
                    default:
                        break;
                }
            });
        }
    }
}
