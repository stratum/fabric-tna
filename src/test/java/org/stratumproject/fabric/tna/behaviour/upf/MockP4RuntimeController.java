// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.behaviour.upf;

import io.grpc.ManagedChannel;
import org.onosproject.net.DeviceId;
import org.onosproject.net.device.DeviceAgentListener;
import org.onosproject.net.pi.model.PiPipeconf;
import org.onosproject.net.pi.runtime.PiPacketOperation;
import org.onosproject.net.provider.ProviderId;
import org.onosproject.p4runtime.api.P4RuntimeClient;
import org.onosproject.p4runtime.api.P4RuntimeController;
import org.onosproject.p4runtime.api.P4RuntimeEventListener;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.concurrent.CompletableFuture;

/**
 * Currently only used to get mock clients that mock counter read requests.
 */
public class MockP4RuntimeController implements P4RuntimeController {

    @Override
    public P4RuntimeClient get(DeviceId deviceId) {
        return new P4RuntimeClient() {
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
            public CompletableFuture<Boolean> setPipelineConfig(long p4DeviceId,
                                                                PiPipeconf pipeconf, ByteBuffer deviceData) {
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
                return new MockReadRequest();
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
                return null;
            }
        };
    }

    @Override
    public void addListener(P4RuntimeEventListener listener) {

    }

    @Override
    public void removeListener(P4RuntimeEventListener listener) {

    }

    @Override
    public boolean create(DeviceId deviceId, ManagedChannel channel) {
        return false;
    }

    @Override
    public void remove(DeviceId deviceId) {

    }

    @Override
    public void addDeviceAgentListener(DeviceId deviceId, ProviderId providerId, DeviceAgentListener listener) {

    }

    @Override
    public void removeDeviceAgentListener(DeviceId deviceId, ProviderId providerId) {

    }
}
