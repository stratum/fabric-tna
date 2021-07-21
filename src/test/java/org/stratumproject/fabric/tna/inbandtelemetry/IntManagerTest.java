// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package org.stratumproject.fabric.tna.inbandtelemetry;

import java.io.InputStream;
import java.util.concurrent.CompletableFuture;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableList;

import org.easymock.Capture;
import org.easymock.EasyMockRunner;
import org.easymock.EasyMockSupport;
import org.easymock.Mock;
import org.easymock.TestSubject;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.onosproject.TestApplicationId;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.mastership.MastershipService;
import org.onosproject.net.Device;
import org.onosproject.net.DeviceId;
import org.onosproject.net.config.NetworkConfigEvent;
import org.onosproject.net.config.NetworkConfigListener;
import org.onosproject.net.config.NetworkConfigRegistry;
import org.onosproject.net.config.NetworkConfigService;
import org.onosproject.net.device.DeviceEvent;
import org.onosproject.net.device.DeviceListener;
import org.onosproject.net.device.DeviceService;

import static org.easymock.EasyMock.anyObject;
import static org.easymock.EasyMock.capture;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.expectLastCall;
import static org.easymock.EasyMock.newCapture;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.reset;
import static org.junit.Assert.fail;

/**
 * Unit test for the IntManager class.
 */
@RunWith(EasyMockRunner.class)
public class IntManagerTest extends EasyMockSupport {
    private static final String APP_NAME = "org.stratumproject.fabric.tna.inbandtelemetry";
    private static final ApplicationId APP_ID = new TestApplicationId(APP_NAME);
    private static final DeviceId DEVICE_ID_1 = DeviceId.deviceId("device:leaf1");
    private static final DeviceId DEVICE_ID_2 = DeviceId.deviceId("device:leaf2");
    private static final String INT_REPORT_CONFIG_KEY = "report";
    private static final IntReportConfig INT_CONFIG_1 = getIntReportConfig("/int-report.json");
    private static final IntReportConfig INT_CONFIG_2 = getIntReportConfig("/int-report-with-subnets.json");

    @Mock
    private CoreService coreService;
    @Mock(fieldName = "netcfgService")
    private NetworkConfigService netcfgService;
    @Mock(fieldName = "netcfgRegistry")
    private NetworkConfigRegistry netcfgRegistry;
    @Mock
    private DeviceService deviceService;
    @Mock
    private MastershipService mastershipService;
    @Mock
    private Device mockDevice;
    @Mock
    private IntProgrammable intProgrammable;
    @TestSubject
    private IntManager intManager = new IntManager();

    private ApplicationId appId;
    private Capture<DeviceListener> deviceListener;
    private Capture<NetworkConfigListener> netcfgListener;

    @Before
    public void setUp() {
        expect(mockDevice.id()).andReturn(DEVICE_ID_1).anyTimes();
        expect(mockDevice.is(IntProgrammable.class)).andReturn(true).anyTimes();
        expect(mockDevice.as(IntProgrammable.class)).andReturn(intProgrammable).anyTimes();
        expect(coreService.registerApplication(APP_NAME)).andReturn(appId).once();
        netcfgRegistry.registerConfigFactory(anyObject());
        expectLastCall().once();
        netcfgListener = newCapture();
        netcfgService.addListener(capture(netcfgListener));
        deviceListener = newCapture();
        deviceService.addListener(capture(deviceListener));
        expect(deviceService.getAvailableDevices()).andReturn(ImmutableList.of(mockDevice)).anyTimes();
        expect(deviceService.isAvailable(anyObject())).andReturn(true).anyTimes();
        expect(mastershipService.isLocalMaster(anyObject())).andReturn(true).anyTimes();
        replay(coreService, netcfgRegistry, deviceService, mastershipService, mockDevice);
    }

    /**
     * Test activating the INT manager with no configuration.
     */
    @Test
    public void testActivateWithoutConfig() {
        expect(netcfgService.getConfig(appId, IntReportConfig.class)).andReturn(null).anyTimes();
        expect(intProgrammable.init()).andReturn(true).once();
        replay(intProgrammable, netcfgService);
        intManager.activate();
        verifyAll();
    }

    /**
     * Test deactivating the INT manager with no configuration.
     */
    @Test
    public void testDeactivateWithoutConfig() {
        testActivateWithoutConfig();
        reset(netcfgService, deviceService, netcfgRegistry, intProgrammable);
        netcfgService.removeListener(netcfgListener.getValue());
        expectLastCall().once();
        deviceService.removeListener(deviceListener.getValue());
        expectLastCall().once();
        netcfgRegistry.unregisterConfigFactory(anyObject());
        expectLastCall().once();
        expect(deviceService.getAvailableDevices()).andReturn(ImmutableList.of(mockDevice)).anyTimes();
        expect(deviceService.isAvailable(anyObject())).andReturn(true).anyTimes();
        expect(intProgrammable.cleanup()).andReturn(true).anyTimes();
        replay(netcfgService, deviceService, netcfgRegistry, intProgrammable);
        intManager.deactivate();
        verifyAll();
    }

    /**
     * Test activating the INT manager with an INT configuration.
     */
    @Test
    public void testActivateWithConfig() {
        expect(netcfgService.getConfig(appId, IntReportConfig.class)).andReturn(INT_CONFIG_1).anyTimes();
        expect(intProgrammable.init()).andReturn(true).once();
        expect(intProgrammable.setUpIntConfig(INT_CONFIG_1)).andReturn(true).once();
        replay(intProgrammable, netcfgService);
        intManager.activate();
        verifyAll();
    }

    /**
     * Test deactivating the INT manager with an INT configuration.
     */
    @Test
    public void testDeactivateWithConfig() {
        testActivateWithConfig();
        reset(netcfgService, deviceService, netcfgRegistry, intProgrammable);
        netcfgService.removeListener(netcfgListener.getValue());
        expectLastCall().once();
        deviceService.removeListener(deviceListener.getValue());
        expectLastCall().once();
        netcfgRegistry.unregisterConfigFactory(anyObject());
        expectLastCall().once();
        expect(deviceService.getAvailableDevices()).andReturn(ImmutableList.of(mockDevice)).anyTimes();
        expect(deviceService.isAvailable(anyObject())).andReturn(true).anyTimes();
        expect(intProgrammable.cleanup()).andReturn(true).anyTimes();
        replay(netcfgService, deviceService, netcfgRegistry, intProgrammable);
        intManager.deactivate();
        verifyAll();
    }

    /**
     * Test updating the INT configuration with the config listener.
     */
    @Test
    public void testUpdateConfig() {
        testActivateWithoutConfig();
        NetworkConfigListener listener = netcfgListener.getValue();
        CompletableFuture<Void> completableFuture = new CompletableFuture<>();
        reset(intProgrammable);
        expect(intProgrammable.setUpIntConfig(INT_CONFIG_2))
                .andAnswer(() -> {
                    completableFuture.complete(null);
                    return true;
                }).once();
        replay(intProgrammable);
        NetworkConfigEvent event = new NetworkConfigEvent(NetworkConfigEvent.Type.CONFIG_UPDATED,
                APP_ID, INT_CONFIG_2, INT_CONFIG_1, IntReportConfig.class);
        listener.event(event);
        completableFuture.join();
        verifyAll();
    }

    /**
     * Test sending new device event to trigger device config update.
     */
    @Test
    public void testAddDevice() {
        testActivateWithConfig();
        DeviceListener listener = deviceListener.getValue();
        CompletableFuture<Void> completableFuture = new CompletableFuture<>();
        Device newDevice = createMock(Device.class);
        IntProgrammable newIntProgrammable = createMock(IntProgrammable.class);
        expect(newDevice.id()).andReturn(DEVICE_ID_2).anyTimes();
        expect(newDevice.is(IntProgrammable.class)).andReturn(true).anyTimes();
        expect(newDevice.as(IntProgrammable.class)).andReturn(newIntProgrammable).anyTimes();
        expect(newIntProgrammable.init()).andReturn(true).once();
        expect(newIntProgrammable.setUpIntConfig(INT_CONFIG_1))
                .andAnswer(() -> {
                    completableFuture.complete(null);
                    return true;
                }).once();
        replay(newDevice, newIntProgrammable);
        DeviceEvent deviceEvent = new DeviceEvent(DeviceEvent.Type.DEVICE_ADDED, newDevice);
        listener.event(deviceEvent);
        completableFuture.join();
        verifyAll();
    }

    /**
     * Gets INT report config from a given JSON file.
     * @param filename the config file path
     * @return the INT report config
     */
    public static IntReportConfig getIntReportConfig(String filename) {
        IntReportConfig config = new IntReportConfig();
        InputStream jsonStream = IntManagerTest.class.getResourceAsStream(filename);
        ObjectMapper mapper = new ObjectMapper();
        JsonNode jsonNode;
        try {
            jsonNode = mapper.readTree(jsonStream);
            config.init(APP_ID, INT_REPORT_CONFIG_KEY, jsonNode, mapper, c -> { });
        } catch (Exception e) {
            fail("Got error when reading file " + filename + " : " + e.getMessage());
        }
        return config;
    }
}
