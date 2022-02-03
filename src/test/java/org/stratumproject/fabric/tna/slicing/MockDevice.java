// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0
package org.stratumproject.fabric.tna.slicing;

import org.onlab.packet.ChassisId;
import org.onosproject.net.Annotations;
import org.onosproject.net.Device;
import org.onosproject.net.DeviceId;
import org.onosproject.net.device.DeviceDescription;
import org.onosproject.net.driver.Behaviour;
import org.onosproject.net.provider.ProviderId;

/**
 * Test implementation of the device.
 * Copied from ONOS repo.
 */
public class MockDevice implements Device {

    private final DeviceDescription desc;
    private final DeviceId id;

    public MockDevice(DeviceId id, DeviceDescription desc) {
        this.desc = desc;
        this.id = id;
    }

    @Override
    public Annotations annotations() {
        return desc.annotations();
    }

    @Override
    public ProviderId providerId() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public <B extends Behaviour> B as(Class<B> projectionClass) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public <B extends Behaviour> boolean is(Class<B> projectionClass) {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public DeviceId id() {
        return id;
    }

    @Override
    public Type type() {
        return desc.type();
    }

    @Override
    public String manufacturer() {
        return desc.manufacturer();
    }

    @Override
    public String hwVersion() {
        return desc.hwVersion();
    }

    @Override
    public String swVersion() {
        return desc.swVersion();
    }

    @Override
    public String serialNumber() {
        return desc.serialNumber();
    }

    @Override
    public ChassisId chassisId() {
        return desc.chassisId();
    }

}
