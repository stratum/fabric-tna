// Copyright 2022-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0

package org.stratumproject.fabric.tna.behaviour.upf;

import com.google.common.collect.Lists;
import org.onosproject.p4runtime.api.P4RuntimeWriteClient;

import java.util.Collection;
import java.util.stream.Collectors;
import java.util.stream.LongStream;

import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;

/**
 * For faking writes to a p4runtime client. Currently, only used for testing
 * UP4-specific counter writes, all other entities are accessed via other ONOS
 * services.
 */
public class MockWriteResponse implements P4RuntimeWriteClient.WriteResponse {

    int numEntities;

    public MockWriteResponse(int numEntities) {
        this.numEntities = numEntities;
    }

    @Override
    public boolean isSuccess() {
        return true;
    }

    @Override
    public Collection<P4RuntimeWriteClient.EntityUpdateResponse> all() {
        P4RuntimeWriteClient.EntityUpdateResponse mockPosResponse =
                createMock(P4RuntimeWriteClient.EntityUpdateResponse.class);
        expect(mockPosResponse.isSuccess())
                .andReturn(true)
                .anyTimes();
        replay(mockPosResponse);
        return LongStream.range(0, numEntities).mapToObj(i -> mockPosResponse).collect(Collectors.toList());
    }

    @Override
    public Collection<P4RuntimeWriteClient.EntityUpdateResponse> success() {
        return all();
    }

    @Override
    public Collection<P4RuntimeWriteClient.EntityUpdateResponse> failed() {
        return Lists.newArrayList();
    }

    @Override
    public Collection<P4RuntimeWriteClient.EntityUpdateResponse> status(
            P4RuntimeWriteClient.EntityUpdateStatus status) {
        return null;
    }
}
