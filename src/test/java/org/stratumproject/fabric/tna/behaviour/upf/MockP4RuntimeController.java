// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.behaviour.upf;

import io.grpc.ManagedChannel;
import org.onosproject.net.DeviceId;
import org.onosproject.net.device.DeviceAgentListener;
import org.onosproject.net.pi.model.PiPipeconf;
import org.onosproject.net.provider.ProviderId;
import org.onosproject.p4runtime.api.P4RuntimeClient;
import org.onosproject.p4runtime.api.P4RuntimeController;
import org.onosproject.p4runtime.api.P4RuntimeEventListener;

import static org.easymock.EasyMock.anyLong;
import static org.easymock.EasyMock.anyObject;
import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;

/**
 * Currently only used to get mock clients that mock counter read requests.
 */
public class MockP4RuntimeController implements P4RuntimeController {

    private final P4RuntimeClient mockP4rtClient;

    /**
     * Used to mock counter read requests.
     *
     * @param deviceId The ID of the device
     * @param packets Packets counter value
     * @param bytes Bytes counter value
     * @param counterSize The size of the counter array
     */
    public MockP4RuntimeController(DeviceId deviceId, long packets, long bytes, int counterSize) {
        mockP4rtClient = createMock(P4RuntimeClient.class);
        expect(mockP4rtClient.read(anyLong(), anyObject(PiPipeconf.class)))
                .andReturn(new MockReadRequest(deviceId, packets, bytes, counterSize))
                .anyTimes();
        replay(mockP4rtClient);
    }

    @Override
    public P4RuntimeClient get(DeviceId deviceId) {
        return mockP4rtClient;
    }

    @Override
    public void addListener(P4RuntimeEventListener listener) {

    }

    @Override
    public void removeListener(P4RuntimeEventListener listener) {

    }

    @Override
    public boolean create(DeviceId deviceId, ManagedChannel channel) {
        return false;
    }

    @Override
    public void remove(DeviceId deviceId) {

    }

    @Override
    public void addDeviceAgentListener(DeviceId deviceId, ProviderId providerId,
                                       DeviceAgentListener listener) {

    }

    @Override
    public void removeDeviceAgentListener(DeviceId deviceId,
                                          ProviderId providerId) {

    }
}
