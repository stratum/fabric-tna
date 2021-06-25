// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.behaviour.upf;

import org.onosproject.store.service.Serializer;
import org.onosproject.store.service.TestConsistentMap;

import static org.stratumproject.fabric.tna.behaviour.upf.DistributedFabricUpfStore.FAR_ID_MAP_NAME;
import static org.stratumproject.fabric.tna.behaviour.upf.DistributedFabricUpfStore.SERIALIZER;

public final class TestDistributedFabricUpfStore {

    private TestDistributedFabricUpfStore() {
    }

    public static DistributedFabricUpfStore build() {
        var store = new DistributedFabricUpfStore();
        TestConsistentMap.Builder<UpfRuleIdentifier, Integer> farIdMapBuilder =
                TestConsistentMap.builder();
        farIdMapBuilder.withName(FAR_ID_MAP_NAME)
                .withRelaxedReadConsistency()
                .withSerializer(Serializer.using(SERIALIZER.build()));
        store.farIdMap = farIdMapBuilder.build();

        store.activate();

        // Init with some translation state.
        store.farIdMap.put(
                new UpfRuleIdentifier(TestUpfConstants.SESSION_ID, TestUpfConstants.UPLINK_FAR_ID),
                TestUpfConstants.UPLINK_PHYSICAL_FAR_ID);
        store.farIdMap.put(
                new UpfRuleIdentifier(TestUpfConstants.SESSION_ID, TestUpfConstants.DOWNLINK_FAR_ID),
                TestUpfConstants.DOWNLINK_PHYSICAL_FAR_ID);

        return store;
    }
}
