// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package org.stratumproject.fabric.tna.inbandtelemetry;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;

import org.easymock.Capture;
import org.easymock.EasyMockRunner;
import org.easymock.EasyMockSupport;
import org.easymock.Mock;
import org.easymock.TestSubject;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.onlab.packet.IpAddress;
import org.onlab.packet.VlanId;
import org.onlab.packet.MacAddress;
import org.onosproject.TestApplicationId;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.mastership.MastershipListener;
import org.onosproject.mastership.MastershipService;
import org.onosproject.net.DefaultHost;
import org.onosproject.net.Device;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Host;
import org.onosproject.net.HostId;
import org.onosproject.net.HostLocation;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.config.NetworkConfigEvent;
import org.onosproject.net.config.NetworkConfigListener;
import org.onosproject.net.config.NetworkConfigRegistry;
import org.onosproject.net.config.NetworkConfigService;
import org.onosproject.net.device.DeviceEvent;
import org.onosproject.net.device.DeviceListener;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.host.HostEvent;
import org.onosproject.net.host.HostListener;
import org.onosproject.net.host.HostService;
import org.onosproject.net.provider.ProviderId;
import org.onosproject.segmentrouting.config.SegmentRoutingDeviceConfig;

import static org.easymock.EasyMock.anyObject;
import static org.easymock.EasyMock.capture;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.newCapture;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.reset;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.stratumproject.fabric.tna.utils.TestUtils.getIntReportConfig;
import static org.stratumproject.fabric.tna.utils.TestUtils.getSrConfig;

/**
 * Unit test for the IntManager class.
 */
@RunWith(EasyMockRunner.class)
public class IntManagerTest extends EasyMockSupport {
    private static final String APP_NAME = "org.stratumproject.fabric.tna.inbandtelemetry";
    private static final ApplicationId APP_ID = new TestApplicationId(APP_NAME);
    private static final DeviceId DEVICE_ID_1 = DeviceId.deviceId("device:leaf1");
    private static final DeviceId DEVICE_ID_2 = DeviceId.deviceId("device:leaf2");
    private static final IntReportConfig INT_CONFIG_1 = getIntReportConfig(APP_ID, "/int-report.json");
    private static final IntReportConfig INT_CONFIG_2 = getIntReportConfig(APP_ID, "/int-report-with-subnets.json");
    private static final SegmentRoutingDeviceConfig SR_CONFIG_1 = getSrConfig(DEVICE_ID_1, "/sr.json");
    private static final IpAddress COLLECTOR_IP = IpAddress.valueOf("10.128.0.1");
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
    private HostService hostService;
    @Mock
    private Device mockDevice;
    @Mock
    private IntProgrammable intProgrammable;
    @TestSubject
    private IntManager intManager = new IntManager();

    private Capture<DeviceListener> deviceListener;
    private Capture<NetworkConfigListener> intConfigListener;
    private Capture<NetworkConfigListener> srConfigListener;
    private Capture<HostListener> hostListener;
    private Capture<MastershipListener> mastershipListener;

    @Before
    public void setUp() {
        expect(mockDevice.id()).andReturn(DEVICE_ID_1).anyTimes();
        expect(mockDevice.is(IntProgrammable.class)).andReturn(true).anyTimes();
        expect(mockDevice.as(IntProgrammable.class)).andReturn(intProgrammable).anyTimes();
        expect(coreService.registerApplication(APP_NAME)).andReturn(APP_ID).once();
        netcfgRegistry.registerConfigFactory(anyObject());
        intConfigListener = newCapture();
        netcfgService.addListener(capture(intConfigListener));
        srConfigListener = newCapture();
        netcfgService.addListener(capture(srConfigListener));
        deviceListener = newCapture();
        deviceService.addListener(capture(deviceListener));
        hostListener = newCapture();
        hostService.addListener(capture(hostListener));
        mastershipListener = newCapture();
        mastershipService.addListener(capture(mastershipListener));
        expect(deviceService.getAvailableDevices()).andReturn(ImmutableList.of(mockDevice)).anyTimes();
        expect(deviceService.isAvailable(anyObject())).andReturn(true).anyTimes();
        expect(mastershipService.isLocalMaster(anyObject())).andReturn(true).anyTimes();
        replay(coreService, netcfgRegistry, deviceService, mastershipService, mockDevice, hostService);
    }

    /**
     * Test activating the INT manager with no configuration.
     */
    @Test
    public void testActivateWithoutConfig() {
        expect(netcfgService.getConfig(APP_ID, IntReportConfig.class)).andReturn(null).anyTimes();
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
        expectedDeactivateProcess();
        intManager.deactivate();
        verifyAll();
    }

    /**
     * Test activating the INT manager with an INT configuration.
     */
    @Test
    public void testActivateWithConfig() {
        expect(netcfgService.getConfig(APP_ID, IntReportConfig.class)).andReturn(INT_CONFIG_1).anyTimes();
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
        expectedDeactivateProcess();
        intManager.deactivate();
        verifyAll();
    }

    /**
     * Test updating the INT configuration with the config listener.
     */
    @Test
    public void testUpdateIntConfig() {
        testActivateWithoutConfig();
        NetworkConfigListener listener = intConfigListener.getValue();
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
        assertTrue(listener.isRelevant(event));
        listener.event(event);
        try {
            completableFuture.get(1, TimeUnit.SECONDS);
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            fail("Didn't get expected call within 1 second.");
        }
        verifyAll();
    }

    /**
     * Test updating the segment routing device configuration with the config listener.
     */
    @Test
    public void testUpdateSrConfig() {
        testActivateWithoutConfig();
        NetworkConfigListener listener = srConfigListener.getValue();
        CompletableFuture<Void> completableFuture = new CompletableFuture<>();
        reset(intProgrammable, netcfgService, deviceService, mastershipService);
        expect(netcfgService.getConfig(APP_ID, IntReportConfig.class)).andReturn(INT_CONFIG_1).anyTimes();
        expect(intProgrammable.setUpIntConfig(INT_CONFIG_1))
                .andAnswer(() -> {
                    completableFuture.complete(null);
                    return true;
                }).once();
        expect(deviceService.getDevice(DEVICE_ID_1)).andReturn(mockDevice).anyTimes();
        expect(deviceService.isAvailable(DEVICE_ID_1)).andReturn(true).anyTimes();
        expect(mastershipService.isLocalMaster(DEVICE_ID_1)).andReturn(true).anyTimes();
        replay(intProgrammable, netcfgService, deviceService, mastershipService);
        NetworkConfigEvent event = new NetworkConfigEvent(NetworkConfigEvent.Type.CONFIG_ADDED,
                APP_ID, SR_CONFIG_1, null, SegmentRoutingDeviceConfig.class);
        assertTrue(listener.isRelevant(event));
        listener.event(event);
        try {
            completableFuture.get(1, TimeUnit.SECONDS);
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            fail("Didn't get expected call within 1 second.");
        }
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
        try {
            completableFuture.get(1, TimeUnit.SECONDS);
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            fail("Didn't get expected call within 1 second.");
        }
        verifyAll();
    }

    /**
     * Test activating the INT manager with an INT configuration. but the device is not
     * managed by this ONOS node.
     */
    @Test
    public void testActivateWithConfigButDeviceIsNotLocal() {
        reset(mastershipService);
        expect(mastershipService.isLocalMaster(anyObject())).andReturn(false).anyTimes();
        mastershipService.addListener(anyObject());
        expect(netcfgService.getConfig(APP_ID, IntReportConfig.class)).andReturn(INT_CONFIG_1).anyTimes();
        replay(intProgrammable, netcfgService, mastershipService);
        intManager.activate();
        verifyAll();
    }

    /**
     * Test activating the INT manager with an INT configuration. but the device is not
     * INT programmable.
     */
    @Test
    public void testWithNonIntProgDevice() {
        reset(mockDevice);
        expect(mockDevice.is(IntProgrammable.class)).andReturn(false).anyTimes();
        expect(netcfgService.getConfig(APP_ID, IntReportConfig.class)).andReturn(INT_CONFIG_1).anyTimes();
        replay(intProgrammable, netcfgService, mockDevice);
        intManager.activate();
        verifyAll();
    }

    /**
     * Test when receving an host event with IP address of the collector.
     */
    @Test
    public void testWithHostEvent() {
        testActivateWithConfig();
        Host host = new DefaultHost(
            new ProviderId("of", "foo"),
            HostId.hostId("00:00:00:00:00:01/None"),
            MacAddress.valueOf("00:00:00:00:00:01"),
            VlanId.NONE,
            new HostLocation(ConnectPoint.fromString("device:leaf1/1"), 0),
            ImmutableSet.of(COLLECTOR_IP)
        );
        HostListener listener = hostListener.getValue();
        CompletableFuture<Void> completableFuture = new CompletableFuture<>();
        reset(intProgrammable, netcfgService, deviceService, mastershipService);
        expect(netcfgService.getConfig(APP_ID, IntReportConfig.class)).andReturn(INT_CONFIG_1).anyTimes();
        expect(intProgrammable.setUpIntConfig(INT_CONFIG_1))
                .andAnswer(() -> {
                    completableFuture.complete(null);
                    return true;
                }).once();
        expect(deviceService.getAvailableDevices()).andReturn(ImmutableList.of(mockDevice)).anyTimes();
        expect(deviceService.isAvailable(DEVICE_ID_1)).andReturn(true).anyTimes();
        expect(mastershipService.isLocalMaster(DEVICE_ID_1)).andReturn(true).anyTimes();
        replay(intProgrammable, netcfgService, deviceService, mastershipService);
        HostEvent hostEvent = new HostEvent(HostEvent.Type.HOST_ADDED, host);
        listener.event(hostEvent);
        try {
            completableFuture.get(1, TimeUnit.SECONDS);
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            fail("Didn't get expected call within 1 second.");
        }
        verifyAll();
    }

    private void expectedDeactivateProcess() {
        reset(netcfgService, deviceService, netcfgRegistry, intProgrammable, hostService, mastershipService);
        netcfgService.removeListener(intConfigListener.getValue());
        netcfgService.removeListener(srConfigListener.getValue());
        deviceService.removeListener(deviceListener.getValue());
        hostService.removeListener(hostListener.getValue());
        mastershipService.removeListener(mastershipListener.getValue());
        netcfgRegistry.unregisterConfigFactory(anyObject());
        expect(deviceService.getAvailableDevices()).andReturn(ImmutableList.of(mockDevice)).anyTimes();
        expect(deviceService.isAvailable(anyObject())).andReturn(true).anyTimes();
        expect(intProgrammable.cleanup()).andReturn(true).anyTimes();
        expect(mastershipService.isLocalMaster(anyObject())).andReturn(true).anyTimes();
        replay(netcfgService, deviceService, netcfgRegistry, intProgrammable, hostService, mastershipService);
    }
}
