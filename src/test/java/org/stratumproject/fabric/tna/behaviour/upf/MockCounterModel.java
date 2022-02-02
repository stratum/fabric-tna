// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0
package org.stratumproject.fabric.tna.behaviour.upf;

import org.onosproject.net.pi.model.PiCounterId;
import org.onosproject.net.pi.model.PiCounterModel;
import org.onosproject.net.pi.model.PiCounterType;
import org.onosproject.net.pi.model.PiTableId;

public class MockCounterModel implements PiCounterModel {
    PiCounterId id;
    int size;

    public MockCounterModel(PiCounterId id, int size) {
        this.id = id;
        this.size = size;
    }

    @Override
    public PiCounterId id() {
        return this.id;
    }

    @Override
    public PiCounterType counterType() {
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
