// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.behaviour.upf;

import org.onlab.packet.Ip4Address;
import org.onosproject.pipelines.fabric.behaviour.upf.UpfRuleIdentifier;
import org.onosproject.store.service.Serializer;
import org.onosproject.store.service.TestConsistentMap;
import org.onosproject.store.service.TestDistributedSet;

import java.util.Set;

import static org.stratumproject.fabric.tna.behaviour.upf.DistributedFabricUpfStore.BUFFER_FAR_ID_SET_NAME;
import static org.stratumproject.fabric.tna.behaviour.upf.DistributedFabricUpfStore.FAR_ID_MAP_NAME;
import static org.stratumproject.fabric.tna.behaviour.upf.DistributedFabricUpfStore.FAR_ID_UE_MAP_NAME;
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

        TestDistributedSet.Builder<UpfRuleIdentifier> bufferFarIdsBuilder =
                TestDistributedSet.builder();
        bufferFarIdsBuilder
                .withName(BUFFER_FAR_ID_SET_NAME)
                .withRelaxedReadConsistency()
                .withSerializer(Serializer.using(SERIALIZER.build()));
        store.bufferFarIds = bufferFarIdsBuilder.build().asDistributedSet();

        TestConsistentMap.Builder<UpfRuleIdentifier, Set<Ip4Address>> farIdToUeAddrsBuilder =
                TestConsistentMap.builder();
        farIdToUeAddrsBuilder
                .withName(FAR_ID_UE_MAP_NAME)
                .withRelaxedReadConsistency()
                .withSerializer(Serializer.using(SERIALIZER.build()));
        store.farIdToUeAddrs = farIdToUeAddrsBuilder.build();

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
