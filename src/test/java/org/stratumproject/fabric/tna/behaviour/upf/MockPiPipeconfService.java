// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.behaviour.upf;

import org.onosproject.net.DeviceId;
import org.onosproject.net.pi.model.PiCounterModel;
import org.onosproject.net.pi.model.PiPipeconf;
import org.onosproject.net.pi.model.PiPipeconfId;
import org.onosproject.net.pi.model.PiTableModel;
import org.onosproject.net.pi.service.PiPipeconfListener;
import org.onosproject.net.pi.service.PiPipeconfService;

import java.util.Collection;
import java.util.Optional;

import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;

public class MockPiPipeconfService implements PiPipeconfService {

    private final PiPipeconf mockPiPipeconf;

    public MockPiPipeconfService(Collection<PiTableModel> tables,
                                 Collection<PiCounterModel> counters) {
        mockPiPipeconf = createMock(PiPipeconf.class);
        expect(mockPiPipeconf.pipelineModel())
                .andReturn(new MockPiPipelineModel(tables, counters))
                .anyTimes();
        replay(mockPiPipeconf);
    }

    @Override
    public Optional<PiPipeconf> getPipeconf(PiPipeconfId id) {
        return Optional.of(mockPiPipeconf);
    }

    @Override
    public Optional<PiPipeconf> getPipeconf(DeviceId deviceId) {
        return Optional.of(mockPiPipeconf);
    }

    @Override
    public void register(PiPipeconf pipeconf) throws IllegalStateException {

    }

    @Override
    public void unregister(PiPipeconfId pipeconfId) throws IllegalStateException {

    }

    @Override
    public Iterable<PiPipeconf> getPipeconfs() {
        return null;
    }

    @Override
    public void bindToDevice(PiPipeconfId pipeconfId, DeviceId deviceId) {

    }

    @Override
    public String getMergedDriver(DeviceId deviceId, PiPipeconfId pipeconfId) {
        return null;
    }

    @Override
    public Optional<PiPipeconfId> ofDevice(DeviceId deviceId) {
        return Optional.empty();
    }

    @Override
    public void addListener(PiPipeconfListener listener) {

    }

    @Override
    public void removeListener(PiPipeconfListener listener) {

    }
}
