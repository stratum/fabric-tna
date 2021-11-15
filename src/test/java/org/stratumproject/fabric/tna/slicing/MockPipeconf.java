// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.slicing;

import org.onosproject.net.driver.Behaviour;
import org.onosproject.net.pi.model.PiPipeconf;
import org.onosproject.net.pi.model.PiPipeconfId;
import org.onosproject.net.pi.model.PiPipelineModel;

import java.io.InputStream;
import java.util.Collection;
import java.util.Optional;

public class MockPipeconf implements PiPipeconf {

    private final PiPipeconfId pipeconfId;
    private final PiPipelineModel pipelineModel;

    public MockPipeconf(PiPipeconfId pipeconfId, PiPipelineModel pipelineModel) {
        this.pipeconfId = pipeconfId;
        this.pipelineModel = pipelineModel;
    }

    @Override
    public PiPipeconfId id() {
        return pipeconfId;
    }

    @Override
    public PiPipelineModel pipelineModel() {
        return this.pipelineModel;
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
}
