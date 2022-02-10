// Copyright 2022-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0
package org.stratumproject.fabric.tna.behaviour.upf;

import org.onosproject.net.pi.model.PiMeterId;
import org.onosproject.net.pi.model.PiMeterModel;
import org.onosproject.net.pi.model.PiMeterType;
import org.onosproject.net.pi.model.PiTableId;

public class MockMeterModel implements PiMeterModel {
    PiMeterId id;
    int size;

    public MockMeterModel(PiMeterId id, int size) {
        this.id = id;
        this.size = size;
    }

    @Override
    public PiMeterId id() {
        return this.id;
    }

    @Override
    public PiMeterType meterType() {
        return null;
    }

    @Override
    public Unit unit() {
        return null;
    }

    @Override
    public PiTableId table() {
        return null;
    }

    @Override
    public long size() {
        return this.size;
    }
}
