// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.behaviour.upf;

import org.onosproject.net.behaviour.upf.PacketDetectionRule;
import org.onosproject.store.service.Serializer;
import org.onosproject.store.service.TestConsistentMap;
import org.onosproject.store.service.TestEventuallyConsistentMap;
import org.onosproject.store.service.WallClockTimestamp;

import static org.stratumproject.fabric.tna.behaviour.upf.DistributedFabricUpfStore.FAR_ID_MAP_NAME;
import static org.stratumproject.fabric.tna.behaviour.upf.DistributedFabricUpfStore.PDR_MATCH_TO_QFI;
import static org.stratumproject.fabric.tna.behaviour.upf.DistributedFabricUpfStore.SERIALIZER;
import static org.stratumproject.fabric.tna.behaviour.upf.TestUpfConstants.DOWNLINK_TC;
import static org.stratumproject.fabric.tna.behaviour.upf.TestUpfConstants.UPLINK_TC;

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

        TestConsistentMap.Builder<PacketDetectionRule, Integer> pdrMatchToQfi =
                TestConsistentMap.builder();
        pdrMatchToQfi.withName(PDR_MATCH_TO_QFI)
                .withRelaxedReadConsistency()
                .withSerializer(Serializer.using(SERIALIZER.build()));
        store.pdrMatchToQfi = pdrMatchToQfi.build();

        store.activate();

        // Init with some translation state.
        store.reverseFarIdMap.put(TestUpfConstants.UPLINK_PHYSICAL_FAR_ID,
                new UpfRuleIdentifier(TestUpfConstants.SESSION_ID, TestUpfConstants.UPLINK_FAR_ID));
        store.reverseFarIdMap.put(TestUpfConstants.DOWNLINK_PHYSICAL_FAR_ID,
                new UpfRuleIdentifier(TestUpfConstants.SESSION_ID, TestUpfConstants.DOWNLINK_FAR_ID));
        store.pdrMatchToQfi.put(TestUpfConstants.UPLINK_QOS_PDR.withoutActionParams(), UPLINK_TC);
        store.pdrMatchToQfi.put(TestUpfConstants.DOWNLINK_QOS_PDR.withoutActionParams(), DOWNLINK_TC);

        return store;
    }
}
