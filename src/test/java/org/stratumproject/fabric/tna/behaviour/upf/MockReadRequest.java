// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.behaviour.upf;

import org.onosproject.net.DeviceId;
import org.onosproject.net.pi.model.PiActionProfileId;
import org.onosproject.net.pi.model.PiCounterId;
import org.onosproject.net.pi.model.PiMeterId;
import org.onosproject.net.pi.model.PiTableId;
import org.onosproject.net.pi.runtime.PiCounterCellHandle;
import org.onosproject.net.pi.runtime.PiCounterCellId;
import org.onosproject.net.pi.runtime.PiHandle;
import org.onosproject.p4runtime.api.P4RuntimeReadClient;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.stream.LongStream;

import static com.google.common.base.Preconditions.checkNotNull;

/**
 * For faking reads to a p4runtime client. Currently only used for testing
 * UP4-specific counter reads, because all other P4 entities that UP4 reads can
 * be read via other ONOS services.
 */
public class MockReadRequest implements P4RuntimeReadClient.ReadRequest {
    List<PiHandle> handles;
    DeviceId deviceId;
    long packets;
    long bytes;
    int counterSize;

    public MockReadRequest(DeviceId deviceId, long packets, long bytes, int counterSize) {
        this.handles = new ArrayList<>();
        this.deviceId = deviceId;
        this.packets = packets;
        this.bytes = bytes;
        this.counterSize = counterSize;
    }

    @Override
    public CompletableFuture<P4RuntimeReadClient.ReadResponse> submit() {
        return CompletableFuture.completedFuture(
                new MockReadResponse(this.handles, this.packets, this.bytes));
    }

    @Override
    public P4RuntimeReadClient.ReadResponse submitSync() {
        return new MockReadResponse(this.handles, this.packets, this.bytes);
    }


    @Override
    public P4RuntimeReadClient.ReadRequest handle(PiHandle handle) {
        this.handles.add(handle);
        return this;
    }

    @Override
    public P4RuntimeReadClient.ReadRequest handles(Iterable<? extends PiHandle> handles) {
        checkNotNull(handles);
        handles.forEach(this::handle);
        return this;
    }

    @Override
    public P4RuntimeReadClient.ReadRequest tableEntries(PiTableId tableId) {
        return this;
    }

    @Override
    public P4RuntimeReadClient.ReadRequest tableEntries(Iterable<PiTableId> tableIds) {
        return this;
    }

    @Override
    public P4RuntimeReadClient.ReadRequest defaultTableEntry(PiTableId tableId) {
        return this;
    }

    @Override
    public P4RuntimeReadClient.ReadRequest defaultTableEntry(Iterable<PiTableId> tableIds) {
        return this;
    }

    @Override
    public P4RuntimeReadClient.ReadRequest allTableEntries() {
        return null;
    }

    @Override
    public P4RuntimeReadClient.ReadRequest allDefaultTableEntries() {
        return null;
    }

    @Override
    public P4RuntimeReadClient.ReadRequest actionProfileGroups(PiActionProfileId actionProfileId) {
        return this;
    }

    @Override
    public P4RuntimeReadClient.ReadRequest actionProfileGroups(Iterable<PiActionProfileId> actionProfileIds) {
        return this;
    }

    @Override
    public P4RuntimeReadClient.ReadRequest actionProfileMembers(PiActionProfileId actionProfileId) {
        return this;
    }

    @Override
    public P4RuntimeReadClient.ReadRequest actionProfileMembers(Iterable<PiActionProfileId> actionProfileIds) {
        return this;
    }

    @Override
    public P4RuntimeReadClient.ReadRequest counterCells(PiCounterId counterId) {
        return this;
    }

    @Override
    public P4RuntimeReadClient.ReadRequest counterCells(Iterable<PiCounterId> counterIds) {
        counterIds.forEach(counterId -> {
            LongStream.range(0, this.counterSize)
                    .forEach(index -> {
                        PiCounterCellId cellId =
                                PiCounterCellId.ofIndirect(counterId, index);
                        PiCounterCellHandle handle =
                                PiCounterCellHandle.of(this.deviceId, cellId);
                        this.handle(handle);
                    });
        });
        return this;
    }

    @Override
    public P4RuntimeReadClient.ReadRequest directCounterCells(PiTableId tableId) {
        return this;
    }

    @Override
    public P4RuntimeReadClient.ReadRequest directCounterCells(Iterable<PiTableId> tableIds) {
        return this;
    }

    @Override
    public P4RuntimeReadClient.ReadRequest meterCells(PiMeterId meterId) {
        return this;
    }

    @Override
    public P4RuntimeReadClient.ReadRequest meterCells(Iterable<PiMeterId> meterIds) {
        return this;
    }

    @Override
    public P4RuntimeReadClient.ReadRequest directMeterCells(PiTableId tableId) {
        return this;
    }

    @Override
    public P4RuntimeReadClient.ReadRequest directMeterCells(Iterable<PiTableId> tableIds) {
        return this;
    }
}
