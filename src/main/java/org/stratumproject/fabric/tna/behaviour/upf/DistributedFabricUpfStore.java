// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.behaviour.upf;

import com.google.common.hash.HashCode;
import com.google.common.hash.HashFunction;
import com.google.common.hash.Hashing;
import org.onlab.util.ImmutableByteSequence;
import org.onlab.util.KryoNamespace;
import org.onosproject.net.behaviour.upf.PacketDetectionRule;
import org.onosproject.store.serializers.KryoNamespaces;
import org.onosproject.store.service.ConsistentMap;
import org.onosproject.store.service.EventuallyConsistentMap;
import org.onosproject.store.service.Serializer;
import org.onosproject.store.service.StorageService;
import org.onosproject.store.service.Versioned;
import org.onosproject.store.service.WallClockTimestamp;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.stream.Collectors;

/**
 * Distributed implementation of FabricUpfStore.
 */
// FIXME: this store is generic and not tied to a single device, should we have a store based on deviceId?
@Component(immediate = true, service = DistributedFabricUpfStore.class)
public final class DistributedFabricUpfStore implements FabricUpfStore {

    private final Logger log = LoggerFactory.getLogger(getClass());

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected StorageService storageService;

    protected static final String FAR_ID_MAP_NAME = "fabric-upf-far-id-tna";
    protected static final String PDR_MATCH_TO_QFI = "pdr-match-to-qfi";
    protected static final KryoNamespace.Builder SERIALIZER = KryoNamespace.newBuilder()
            .register(KryoNamespaces.API)
            .register(UpfRuleIdentifier.class);

    // EC map to remember the mapping far_id -> rule_id this is mostly used during reads,
    // it can be definitely removed by simplifying the logical pipeline
    protected EventuallyConsistentMap<Integer, UpfRuleIdentifier> reverseFarIdMap;

    // Used to remember the QFI. Currently we don't store the QFI on the flow rule
    // and data plane requires the TC. We need a way to retrieve the original QFI
    // when building the PDR starting from the installed flow rule.
    // TODO: add QFI into flow rule and remove this ConsistentMap.
    protected ConsistentMap<PacketDetectionRule, Integer> pdrMatchToQfi;

    @Activate
    protected void activate() {
        // Allow unit test to inject reverseFarIdMap here.
        if (storageService != null) {
            this.reverseFarIdMap = storageService.<Integer, UpfRuleIdentifier>eventuallyConsistentMapBuilder()
                    .withName(FAR_ID_MAP_NAME)
                    .withSerializer(SERIALIZER)
                    .withTimestampProvider((k, v) -> new WallClockTimestamp())
                    .build();
            this.pdrMatchToQfi = storageService.<PacketDetectionRule, Integer>consistentMapBuilder()
                    .withName(PDR_MATCH_TO_QFI)
                    .withRelaxedReadConsistency()
                    .withSerializer(Serializer.using(SERIALIZER.build()))
                    .build();
        }

        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {
        reverseFarIdMap.destroy();

        log.info("Stopped");
    }

    @Override
    public void reset() {
        reverseFarIdMap.clear();
    }

    @Override
    public Map<Integer, UpfRuleIdentifier> getReverseFarIdMap() {
        return reverseFarIdMap.entrySet().stream()
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }

    @Override
    public int globalFarIdOf(UpfRuleIdentifier farIdPair) {
        int globalFarId = getGlobalFarIdOf(farIdPair);
        reverseFarIdMap.put(globalFarId, farIdPair);
        log.info("{} translated to GlobalFarId={}", farIdPair, globalFarId);
        return globalFarId;
    }

    @Override
    public int removeGlobalFarId(UpfRuleIdentifier farIdPair) {
        int globalFarId = getGlobalFarIdOf(farIdPair);
        reverseFarIdMap.remove(globalFarId);
        return globalFarId;
    }

    @Override
    public int globalFarIdOf(ImmutableByteSequence pfcpSessionId, int sessionLocalFarId) {
        UpfRuleIdentifier farId = new UpfRuleIdentifier(pfcpSessionId, sessionLocalFarId);
        return globalFarIdOf(farId);

    }

    @Override
    public int removeGlobalFarId(ImmutableByteSequence pfcpSessionId, int sessionLocalFarId) {
        UpfRuleIdentifier farId = new UpfRuleIdentifier(pfcpSessionId, sessionLocalFarId);
        return removeGlobalFarId(farId);
    }

    @Override
    public Integer pdrMatchToQfi(PacketDetectionRule pdr) {
        return Versioned.valueOrNull(pdrMatchToQfi.get(pdr.withoutActionParams()));
    }

    @Override
    public void addPdrMatchToQfi(PacketDetectionRule pdr, int qfi) {
        // Key is the match part of the PDR
        pdrMatchToQfi.put(pdr.withoutActionParams(), qfi);
    }

    @Override
    public UpfRuleIdentifier localFarIdOf(int globalFarId) {
        return reverseFarIdMap.get(globalFarId);
    }

    // Compute global far id by hashing the pfcp session id and the session local far
    private int getGlobalFarIdOf(UpfRuleIdentifier farIdPair) {
        HashFunction hashFunction = Hashing.murmur3_32();
        HashCode hashCode = hashFunction.newHasher()
                .putInt(farIdPair.getSessionLocalId())
                .putBytes(farIdPair.getPfcpSessionId().asArray())
                .hash();
        return hashCode.asInt();
    }

}
