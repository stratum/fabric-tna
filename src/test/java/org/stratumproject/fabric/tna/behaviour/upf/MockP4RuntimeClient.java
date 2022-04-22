// Copyright 2022-present Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package org.stratumproject.fabric.tna.behaviour.upf;

import com.google.common.collect.Maps;
import org.onosproject.net.DeviceId;
import org.onosproject.net.pi.model.PiPipeconf;
import org.onosproject.net.pi.runtime.PiCounterCell;
import org.onosproject.net.pi.runtime.PiCounterCellData;
import org.onosproject.net.pi.runtime.PiCounterCellId;
import org.onosproject.net.pi.runtime.PiPacketOperation;
import org.onosproject.p4runtime.api.P4RuntimeClient;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.stream.LongStream;

import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_EGRESS_UPF_TERMINATIONS_COUNTER;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_UPF_TERMINATIONS_COUNTER;

/**
 * Used to mock P4Runtime client used only for read/write requests for counters.
 */
public class MockP4RuntimeClient implements P4RuntimeClient {

    private final DeviceId deviceId;
    private final Map<Long, PiCounterCell> igCounters;
    private final Map<Long, PiCounterCell> egCounters;

    /**
     * Used to mock P4Runtime client.
     *
     * @param deviceId    The ID of the device
     * @param counterSize The size of the counter array
     */
    public MockP4RuntimeClient(DeviceId deviceId, int counterSize) {
        this.deviceId = deviceId;
        igCounters = Maps.newHashMap();
        egCounters = Maps.newHashMap();
        LongStream.range(0, counterSize).forEach(i -> {

        });
        for (long i = 0; i < counterSize; i++) {
            igCounters.put(i, new PiCounterCell(
                    PiCounterCellId.ofIndirect(FABRIC_INGRESS_UPF_TERMINATIONS_COUNTER, i),
                    new PiCounterCellData(0, 0)));
            egCounters.put(i, new PiCounterCell(
                    PiCounterCellId.ofIndirect(FABRIC_EGRESS_UPF_TERMINATIONS_COUNTER, i),
                    new PiCounterCellData(0, 0)));
        }
    }

    @Override
    public void shutdown() {

    }

    @Override
    public boolean isServerReachable() {
        return false;
    }

    @Override
    public CompletableFuture<Boolean> probeService() {
        return null;
    }

    @Override
    public CompletableFuture<Boolean> setPipelineConfig(long p4DeviceId, PiPipeconf pipeconf, ByteBuffer deviceData) {
        return null;
    }

    @Override
    public CompletableFuture<Boolean> isPipelineConfigSet(long p4DeviceId, PiPipeconf pipeconf) {
        return null;
    }

    @Override
    public CompletableFuture<Boolean> isAnyPipelineConfigSet(long p4DeviceId) {
        return null;
    }

    @Override
    public ReadRequest read(long p4DeviceId, PiPipeconf pipeconf) {
        return new MockReadRequest(deviceId, igCounters, egCounters);
    }

    @Override
    public void setMastership(long p4DeviceId, boolean master, BigInteger electionId) {

    }

    @Override
    public boolean isSessionOpen(long p4DeviceId) {
        return false;
    }

    @Override
    public void closeSession(long p4DeviceId) {

    }

    @Override
    public boolean isMaster(long p4DeviceId) {
        return false;
    }

    @Override
    public void packetOut(long p4DeviceId, PiPacketOperation packet, PiPipeconf pipeconf) {

    }

    @Override
    public WriteRequest write(long p4DeviceId, PiPipeconf pipeconf) {
        return new MockWriteRequest(deviceId, igCounters, egCounters);
    }
}
