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
import org.onosproject.mastership.MastershipEvent;
import org.onosproject.mastership.MastershipListener;
import org.onosproject.mastership.MastershipService;
import org.onosproject.net.Device;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Host;
import org.onosproject.net.config.ConfigFactory;
import org.onosproject.net.config.NetworkConfigEvent;
import org.onosproject.net.config.NetworkConfigListener;
import org.onosproject.net.config.NetworkConfigRegistry;
import org.onosproject.net.config.NetworkConfigService;
import org.onosproject.net.config.basics.SubjectFactories;
import org.onosproject.net.device.DeviceEvent;
import org.onosproject.net.device.DeviceListener;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.host.HostEvent;
import org.onosproject.net.host.HostListener;
import org.onosproject.net.host.HostService;
import org.onosproject.segmentrouting.config.SegmentRoutingDeviceConfig;
import org.stratumproject.fabric.tna.Constants;

import static java.util.concurrent.Executors.newSingleThreadScheduledExecutor;
import static org.slf4j.LoggerFactory.getLogger;
import static org.onlab.util.Tools.groupedThreads;

@Component(immediate = true)
public class IntManager {
    private static final Logger log = getLogger(IntManager.class);

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

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected HostService hostService;

    private ApplicationId appId;
    private ExecutorService eventExecutor;
    private final NetworkConfigListener intReportConfigListener = new IntReportConfigListener();
    private final NetworkConfigListener srConfigListener = new SrConfigListener();
    private final DeviceListener deviceListener = new IntDeviceListener();
    private final HostListener hostListener = new CollectorHostListener();
    private final MastershipListener mastershipListener = new DeviceMastershipListener();

    private final ConfigFactory<ApplicationId, IntReportConfig> intAppConfigFactory = new ConfigFactory<>(
            SubjectFactories.APP_SUBJECT_FACTORY, IntReportConfig.class, "report") {
        @Override
        public IntReportConfig createConfig() {
            return new IntReportConfig();
        }
    };

    @Activate
    public void activate() {
        appId = coreService.registerApplication(Constants.APP_NAME_INT);
        eventExecutor = newSingleThreadScheduledExecutor(groupedThreads("onos/int", "events-%d", log));
        netcfgRegistry.registerConfigFactory(intAppConfigFactory);
        netcfgService.addListener(intReportConfigListener);
        netcfgService.addListener(srConfigListener);
        deviceService.addListener(deviceListener);
        hostService.addListener(hostListener);
        mastershipService.addListener(mastershipListener);
        Streams.stream(deviceService.getAvailableDevices()).forEach(this::initDevice);
        IntReportConfig config = netcfgService.getConfig(appId, IntReportConfig.class);
        if (config != null) {
            Streams.stream(deviceService.getAvailableDevices()).forEach(device -> setUpIntConfig(config, device));
        }
        log.info("Started");
    }

    @Deactivate
    public void deactivate() {
        netcfgService.removeListener(intReportConfigListener);
        netcfgService.removeListener(srConfigListener);
        deviceService.removeListener(deviceListener);
        hostService.removeListener(hostListener);
        mastershipService.removeListener(mastershipListener);
        eventExecutor.shutdown();
        netcfgRegistry.unregisterConfigFactory(intAppConfigFactory);
        Streams.stream(deviceService.getAvailableDevices()).forEach(this::cleanupDevice);
        log.info("Stopped");
    }

    private void initDevice(Device device) {
        if (checkDevice(device) && !device.as(IntProgrammable.class).init()) {
            log.warn("Failed to initialize {}", device.id());
        }
    }

    private void cleanupDevice(Device device) {
        if (checkDevice(device) && !device.as(IntProgrammable.class).cleanup()) {
            log.warn("Failed to cleanup {}", device.id());
        }
    }

    private void setUpIntConfig(IntReportConfig config, Device device) {
        if (checkDevice(device) && !device.as(IntProgrammable.class).setUpIntConfig(config)) {
            log.warn("Failed to set up INT report config for device {}", device.id());
        }
    }

    private void setUpIntConfig(IntReportConfig config) {
        Streams.stream(deviceService.getAvailableDevices())
            .forEach(device -> setUpIntConfig(config, device));
    }

    private boolean checkDevice(Device device) {
        return device.is(IntProgrammable.class) &&
                mastershipService.isLocalMaster(device.id()) &&
                deviceService.isAvailable(device.id());
    }

    private class IntReportConfigListener implements NetworkConfigListener {
        @Override
        public void event(NetworkConfigEvent event) {
            eventExecutor.execute(() -> {
                switch (event.type()) {
                    case CONFIG_ADDED:
                    case CONFIG_UPDATED:
                        event.config()
                            .map(IntReportConfig.class::cast)
                            .ifPresent(IntManager.this::setUpIntConfig);
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

    private class IntDeviceListener implements DeviceListener {
        @Override
        public void event(DeviceEvent event) {
            eventExecutor.execute(() -> {
                switch (event.type()) {
                    case DEVICE_ADDED:
                    case DEVICE_AVAILABILITY_CHANGED:
                        Device device = event.subject();
                        initDevice(device);
                        IntReportConfig config = netcfgService.getConfig(appId, IntReportConfig.class);
                        if (config != null) {
                            setUpIntConfig(config, device);
                        }
                        break;
                    default:
                        break;
                }
            });
        }
    }

    /**
     * To check if the segment routing device config is added or updated since it
     * can be loaded after the INT manager is activated or INT config is loaded.
     */
    private class SrConfigListener implements NetworkConfigListener {
        @Override
        public void event(NetworkConfigEvent event) {
            eventExecutor.execute(() -> {
                switch (event.type()) {
                    case CONFIG_ADDED:
                    case CONFIG_UPDATED:
                        event.config()
                            .map(SegmentRoutingDeviceConfig.class::cast)
                            .ifPresent(config -> {
                                IntReportConfig intConfig = netcfgService.getConfig(appId, IntReportConfig.class);
                                if (intConfig != null) {
                                    Device device = deviceService.getDevice(config.subject());
                                    setUpIntConfig(intConfig, device);
                                }
                            });
                        break;
                    default:
                        break;
                }
            });
        }

        @Override
        public boolean isRelevant(NetworkConfigEvent event) {
            return event.configClass() == SegmentRoutingDeviceConfig.class;
        }
    }

    /**
     * To install INT rules when collector host is added.
     */
    private class CollectorHostListener implements HostListener {
        @Override
        public void event(HostEvent event) {
            eventExecutor.execute(() -> {
                IntReportConfig config = netcfgService.getConfig(appId, IntReportConfig.class);
                if (config == null) {
                    return;
                }
                switch (event.type()) {
                    case HOST_ADDED:
                    case HOST_UPDATED:
                        Host host = event.subject();
                        if (host.ipAddresses().contains(config.collectorIp())) {
                            setUpIntConfig(config);
                        }
                        break;
                    default:
                        break;
                }
            });
        }
    }

    /**
     * To install INT rules when this ONOS instance becomes the master of a device.
     */
    private class DeviceMastershipListener implements MastershipListener {

        @Override
        public void event(MastershipEvent event) {
            eventExecutor.execute(() -> {
                IntReportConfig config = netcfgService.getConfig(appId, IntReportConfig.class);
                if (config == null) {
                    return;
                }
                switch (event.type()) {
                    case MASTER_CHANGED:
                        DeviceId deviceId = event.subject();
                        if (mastershipService.isLocalMaster(deviceId)) {
                            setUpIntConfig(config);
                        }
                        break;
                    default:
                        break;
                }
            });
        }
    }
}
