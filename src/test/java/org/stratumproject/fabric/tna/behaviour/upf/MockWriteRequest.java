// Copyright 2022-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0

package org.stratumproject.fabric.tna.behaviour.upf;

import org.onosproject.net.DeviceId;
import org.onosproject.net.pi.runtime.PiCounterCell;
import org.onosproject.net.pi.runtime.PiCounterCellId;
import org.onosproject.net.pi.runtime.PiEntity;
import org.onosproject.net.pi.runtime.PiEntityType;
import org.onosproject.net.pi.runtime.PiHandle;
import org.onosproject.p4runtime.api.P4RuntimeWriteClient;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_EGRESS_UPF_TERMINATIONS_COUNTER;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_UPF_TERMINATIONS_COUNTER;

/**
 * For faking writes to a p4runtime client. Currently, only used for testing
 * UP4-specific counter writes, all other entities are accessed via other ONOS
 * services.
 */
public class MockWriteRequest implements P4RuntimeWriteClient.WriteRequest {
    private final List<PiEntity> toModifyEntities;
    private final DeviceId deviceId;
    private final Map<Long, PiCounterCell> igCounters;
    private final Map<Long, PiCounterCell> egCounters;

    public MockWriteRequest(DeviceId deviceId,
                            Map<Long, PiCounterCell> igCounters,
                            Map<Long, PiCounterCell> egCounters) {
        this.toModifyEntities = new ArrayList<>();
        this.deviceId = deviceId;
        this.igCounters = igCounters;
        this.egCounters = egCounters;
    }

    @Override
    public P4RuntimeWriteClient.WriteRequest withAtomicity(P4RuntimeWriteClient.Atomicity atomicity) {
        return null;
    }

    @Override
    public P4RuntimeWriteClient.WriteRequest insert(PiEntity entity) {
        return null;
    }

    @Override
    public P4RuntimeWriteClient.WriteRequest insert(Iterable<? extends PiEntity> entities) {
        return null;
    }

    @Override
    public P4RuntimeWriteClient.WriteRequest modify(PiEntity entity) {
        toModifyEntities.add(entity);
        return this;
    }

    @Override
    public P4RuntimeWriteClient.WriteRequest modify(Iterable<? extends PiEntity> entities) {
        entities.forEach(toModifyEntities::add);
        return this;
    }

    @Override
    public P4RuntimeWriteClient.WriteRequest delete(PiHandle handle) {
        return null;
    }

    @Override
    public P4RuntimeWriteClient.WriteRequest delete(Iterable<? extends PiHandle> handles) {
        return null;
    }

    @Override
    public P4RuntimeWriteClient.WriteRequest entity(PiEntity entity, P4RuntimeWriteClient.UpdateType updateType) {
        return null;
    }

    @Override
    public P4RuntimeWriteClient.WriteRequest entities(Iterable<? extends PiEntity> entities,
                                                      P4RuntimeWriteClient.UpdateType updateType) {
        return null;
    }

    @Override
    public CompletableFuture<P4RuntimeWriteClient.WriteResponse> submit() {
        modifyEntities();
        return CompletableFuture.completedFuture(
                new MockWriteResponse(toModifyEntities.size()));
    }

    @Override
    public P4RuntimeWriteClient.WriteResponse submitSync() {
        modifyEntities();
        return new MockWriteResponse(toModifyEntities.size());
    }

    private void modifyEntities() {
        // Only handles counter cell so far
        toModifyEntities.forEach(
                entity -> {
                    if (entity.piEntityType().equals(PiEntityType.COUNTER_CELL)) {
                        PiCounterCell counterCell = (PiCounterCell) entity;
                        PiCounterCellId cellId = counterCell.cellId();
                        if (cellId.counterId().equals(FABRIC_INGRESS_UPF_TERMINATIONS_COUNTER)) {
                            igCounters.computeIfPresent(cellId.index(), (k, v) -> counterCell);
                        } else if (cellId.counterId().equals(FABRIC_EGRESS_UPF_TERMINATIONS_COUNTER)) {
                            egCounters.computeIfPresent(cellId.index(), (k, v) -> counterCell);
                        }
                    }
                }
        );
    }

    @Override
    public Collection<P4RuntimeWriteClient.EntityUpdateRequest> pendingUpdates() {
        return null;
    }
}
