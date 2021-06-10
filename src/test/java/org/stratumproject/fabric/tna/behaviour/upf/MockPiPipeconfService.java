// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.behaviour.upf;

import org.onosproject.net.DeviceId;
import org.onosproject.net.driver.Behaviour;
import org.onosproject.net.pi.model.PiPipeconf;
import org.onosproject.net.pi.model.PiPipeconfId;
import org.onosproject.net.pi.model.PiPipelineModel;
import org.onosproject.net.pi.service.PiPipeconfListener;
import org.onosproject.net.pi.service.PiPipeconfService;

import java.io.InputStream;
import java.util.Collection;
import java.util.Optional;

public class MockPiPipeconfService implements PiPipeconfService {
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
    public Optional<PiPipeconf> getPipeconf(PiPipeconfId id) {
        return Optional.of(getFakePiPipeconf());
    }

    private PiPipeconf getFakePiPipeconf() {
        return new PiPipeconf() {
            @Override
            public PiPipeconfId id() {
                return null;
            }

            @Override
            public PiPipelineModel pipelineModel() {
                return new MockPiPipelineModel();
            }

            @Override
            public long fingerprint() {
                return 0;
            }

            @Override
            public Collection<Class<? extends Behaviour>> behaviours() {
                return null;
            }

            @Override
            public Optional<Class<? extends Behaviour>> implementation(Class<? extends Behaviour> behaviour) {
                return Optional.empty();
            }

            @Override
            public boolean hasBehaviour(Class<? extends Behaviour> behaviourClass) {
                return false;
            }

            @Override
            public Optional<InputStream> extension(ExtensionType type) {
                return Optional.empty();
            }
        };
    }

    @Override
    public Optional<PiPipeconf> getPipeconf(DeviceId deviceId) {
        return Optional.of(getFakePiPipeconf());
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
