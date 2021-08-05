// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.behaviour.upf;

import org.onosproject.store.service.TestEventuallyConsistentMap;
import org.onosproject.store.service.WallClockTimestamp;

import static org.stratumproject.fabric.tna.behaviour.upf.DistributedFabricUpfStore.FAR_ID_MAP_NAME;
import static org.stratumproject.fabric.tna.behaviour.upf.DistributedFabricUpfStore.SERIALIZER;

public final class TestDistributedFabricUpfStore {

    private TestDistributedFabricUpfStore() {
    }

    public static DistributedFabricUpfStore build() {
        var store = new DistributedFabricUpfStore();
        TestEventuallyConsistentMap.Builder<Integer, UpfRuleIdentifier> reverseFarIdMapBuilder =
                TestEventuallyConsistentMap.builder();
        reverseFarIdMapBuilder.withName(FAR_ID_MAP_NAME)
                .withTimestampProvider((k, v) -> new WallClockTimestamp())
                .withSerializer(SERIALIZER.build());
        store.reverseFarIdMap = reverseFarIdMapBuilder.build();

        store.activate();

        // Init with some translation state.
        store.reverseFarIdMap.put(TestUpfConstants.UPLINK_PHYSICAL_FAR_ID,
                new UpfRuleIdentifier(TestUpfConstants.SESSION_ID, TestUpfConstants.UPLINK_FAR_ID));
        store.reverseFarIdMap.put(TestUpfConstants.DOWNLINK_PHYSICAL_FAR_ID,
                new UpfRuleIdentifier(TestUpfConstants.SESSION_ID, TestUpfConstants.DOWNLINK_FAR_ID));

        return store;
    }
}
