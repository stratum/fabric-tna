// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0
package org.stratumproject.fabric.tna.behaviour.upf;

import com.google.common.collect.Maps;
import org.onosproject.net.pi.model.PiActionProfileId;
import org.onosproject.net.pi.model.PiActionProfileModel;
import org.onosproject.net.pi.model.PiCounterId;
import org.onosproject.net.pi.model.PiCounterModel;
import org.onosproject.net.pi.model.PiMeterId;
import org.onosproject.net.pi.model.PiMeterModel;
import org.onosproject.net.pi.model.PiPacketOperationModel;
import org.onosproject.net.pi.model.PiPacketOperationType;
import org.onosproject.net.pi.model.PiPipelineModel;
import org.onosproject.net.pi.model.PiRegisterId;
import org.onosproject.net.pi.model.PiRegisterModel;
import org.onosproject.net.pi.model.PiTableId;
import org.onosproject.net.pi.model.PiTableModel;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;


public class MockPiPipelineModel implements PiPipelineModel {

    private final Map<PiTableId, PiTableModel> tableMap = Maps.newHashMap();
    private final String architecture;

    private final List<PiCounterModel> counters;

    public MockPiPipelineModel(Collection<PiTableModel> tables,
                               Collection<PiCounterModel> counters,
                               String architecture) {
        tables.forEach(tableModel -> tableMap.put(tableModel.id(), tableModel));
        this.counters = List.copyOf(counters);
        this.architecture = architecture;
    }

    @Override
    public Optional<String> architecture() {
        return Optional.of(this.architecture);
    }

    @Override
    public Optional<PiTableModel> table(PiTableId tableId) {
        return Optional.ofNullable(tableMap.getOrDefault(tableId, null));
    }

    @Override
    public Collection<PiTableModel> tables() {
        return tableMap.values();
    }

    @Override
    public Optional<PiCounterModel> counter(PiCounterId counterId) {
        return Optional.empty();
    }

    @Override
    public Collection<PiCounterModel> counters() {
        return counters;
    }

    @Override
    public Optional<PiMeterModel> meter(PiMeterId meterId) {
        return Optional.empty();
    }

    @Override
    public Collection<PiMeterModel> meters() {
        return null;
    }

    @Override
    public Optional<PiRegisterModel> register(PiRegisterId registerId) {
        return Optional.empty();
    }

    @Override
    public Collection<PiRegisterModel> registers() {
        return null;
    }

    @Override
    public Optional<PiActionProfileModel> actionProfiles(PiActionProfileId actionProfileId) {
        return Optional.empty();
    }

    @Override
    public Collection<PiActionProfileModel> actionProfiles() {
        return null;
    }

    @Override
    public Optional<PiPacketOperationModel> packetOperationModel(PiPacketOperationType type) {
        return Optional.empty();
    }


}
