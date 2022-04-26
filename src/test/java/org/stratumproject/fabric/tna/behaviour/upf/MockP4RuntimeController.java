// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0
package org.stratumproject.fabric.tna.behaviour.upf;

import io.grpc.ManagedChannel;
import org.onosproject.net.DeviceId;
import org.onosproject.net.device.DeviceAgentListener;
import org.onosproject.net.provider.ProviderId;
import org.onosproject.p4runtime.api.P4RuntimeClient;
import org.onosproject.p4runtime.api.P4RuntimeController;
import org.onosproject.p4runtime.api.P4RuntimeEventListener;

/**
 * Currently only used to get mock clients that mock counter read/write requests.
 */
public class MockP4RuntimeController implements P4RuntimeController {

    private final P4RuntimeClient mockP4rtClient;

    /**
     * Used to mock counter read/write requests.
     *
     * @param deviceId    The ID of the device
     * @param counterSize The size of the counter array
     */
    public MockP4RuntimeController(DeviceId deviceId, int counterSize) {
        mockP4rtClient = new MockP4RuntimeClient(deviceId, counterSize);
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
