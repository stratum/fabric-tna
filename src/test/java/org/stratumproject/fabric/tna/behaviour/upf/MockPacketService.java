// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0
package org.stratumproject.fabric.tna.behaviour.upf;

import com.google.common.collect.Queues;
import org.onosproject.core.ApplicationId;
import org.onosproject.net.DeviceId;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketProcessorEntry;
import org.onosproject.net.packet.PacketRequest;
import org.onosproject.net.packet.PacketService;

import java.util.List;
import java.util.Optional;
import java.util.Queue;

public class MockPacketService implements PacketService {

    Queue<OutboundPacket> emittedPackets = Queues.newArrayDeque();

    @Override
    public void addProcessor(PacketProcessor processor, int priority) {

    }

    @Override
    public void removeProcessor(PacketProcessor processor) {

    }

    @Override
    public List<PacketProcessorEntry> getProcessors() {
        return null;
    }

    @Override
    public void requestPackets(TrafficSelector selector, PacketPriority priority, ApplicationId appId) {

    }

    @Override
    public void requestPackets(TrafficSelector selector, PacketPriority priority,
                               ApplicationId appId, Optional<DeviceId> deviceId) {

    }

    @Override
    public void cancelPackets(TrafficSelector selector, PacketPriority priority, ApplicationId appId) {

    }

    @Override
    public void cancelPackets(TrafficSelector selector, PacketPriority priority,
                              ApplicationId appId, Optional<DeviceId> deviceId) {

    }

    @Override
    public List<PacketRequest> getRequests() {
        return null;
    }

    @Override
    public void emit(OutboundPacket packet) {
        emittedPackets.add(packet);
    }
}


