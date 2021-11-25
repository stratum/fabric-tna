// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.behaviour.upf;

import org.onosproject.net.pi.model.PiActionId;
import org.onosproject.net.pi.model.PiActionModel;
import org.onosproject.net.pi.model.PiActionProfileModel;
import org.onosproject.net.pi.model.PiCounterModel;
import org.onosproject.net.pi.model.PiMatchFieldId;
import org.onosproject.net.pi.model.PiMatchFieldModel;
import org.onosproject.net.pi.model.PiMeterModel;
import org.onosproject.net.pi.model.PiTableId;
import org.onosproject.net.pi.model.PiTableModel;
import org.onosproject.net.pi.model.PiTableType;

import java.util.Collection;
import java.util.Optional;

public class MockTableModel implements PiTableModel {
    PiTableId id;
    int size;

    public MockTableModel(PiTableId id, int size) {
        this.id = id;
        this.size = size;
    }

    @Override
    public PiTableId id() {
        return this.id;
    }

    @Override
    public PiTableType tableType() {
        return null;
    }

    @Override
    public PiActionProfileModel actionProfile() {
        return null;
    }

    @Override
    public long maxSize() {
        return size;
    }

    @Override
    public Collection<PiCounterModel> counters() {
        return null;
    }

    @Override
    public Collection<PiMeterModel> meters() {
        return null;
    }

    @Override
    public boolean supportsAging() {
        return false;
    }

    @Override
    public Collection<PiMatchFieldModel> matchFields() {
        return null;
    }

    @Override
    public Collection<PiActionModel> actions() {
        return null;
    }

    @Override
    public Optional<PiActionModel> constDefaultAction() {
        return Optional.empty();
    }

    @Override
    public boolean isConstantTable() {
        return false;
    }

    @Override
    public boolean oneShotOnly() {
        return false;
    }

    @Override
    public Optional<PiActionModel> action(PiActionId actionId) {
        return Optional.empty();
    }

    @Override
    public Optional<PiMatchFieldModel> matchField(PiMatchFieldId matchFieldId) {
        return Optional.empty();
    }
}
