// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.behaviour.upf;

import com.google.common.collect.Maps;
import org.onlab.util.ImmutableByteSequence;
import org.onlab.util.KryoNamespace;
import org.onosproject.store.serializers.KryoNamespaces;
import org.onosproject.store.service.ConsistentMap;
import org.onosproject.store.service.MapEvent;
import org.onosproject.store.service.MapEventListener;
import org.onosproject.store.service.Serializer;
import org.onosproject.store.service.StorageService;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.Objects;

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
    protected static final KryoNamespace.Builder SERIALIZER = KryoNamespace.newBuilder()
            .register(KryoNamespaces.API)
            .register(UpfRuleIdentifier.class);

    // Distributed local FAR ID to global FAR ID mapping
    protected ConsistentMap<UpfRuleIdentifier, Integer> farIdMap;
    private MapEventListener<UpfRuleIdentifier, Integer> farIdMapListener;
    // Local, reversed copy of farIdMapper for better reverse lookup performance
    protected Map<Integer, UpfRuleIdentifier> reverseFarIdMap;
    private int nextGlobalFarId = 1;

    @Activate
    protected void activate() {
        // Allow unit test to inject farIdMap here.
        if (storageService != null) {
            this.farIdMap = storageService.<UpfRuleIdentifier, Integer>consistentMapBuilder()
                    .withName(FAR_ID_MAP_NAME)
                    .withRelaxedReadConsistency()
                    .withSerializer(Serializer.using(SERIALIZER.build()))
                    .build();

        }
        farIdMapListener = new FarIdMapListener();
        farIdMap.addListener(farIdMapListener);

        reverseFarIdMap = Maps.newHashMap();
        farIdMap.entrySet().forEach(entry -> reverseFarIdMap.put(entry.getValue().value(), entry.getKey()));

        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {
        farIdMap.removeListener(farIdMapListener);
        farIdMap.destroy();
        reverseFarIdMap.clear();

        log.info("Stopped");
    }

    @Override
    public void reset() {
        farIdMap.clear();
        reverseFarIdMap.clear();
        nextGlobalFarId = 0;
    }

    @Override
    public Map<UpfRuleIdentifier, Integer> getFarIdMap() {
        return Map.copyOf(farIdMap.asJavaMap());
    }

    @Override
    public int globalFarIdOf(UpfRuleIdentifier farIdPair) {
        int globalFarId = farIdMap.compute(farIdPair,
                (k, existingId) -> {
                    return Objects.requireNonNullElseGet(existingId, () -> nextGlobalFarId++);
                }).value();
        log.info("{} translated to GlobalFarId={}", farIdPair, globalFarId);
        return globalFarId;
    }

    @Override
    public int globalFarIdOf(ImmutableByteSequence pfcpSessionId, int sessionLocalFarId) {
        UpfRuleIdentifier farId = new UpfRuleIdentifier(pfcpSessionId, sessionLocalFarId);
        return globalFarIdOf(farId);

    }

    @Override
    public UpfRuleIdentifier localFarIdOf(int globalFarId) {
        return reverseFarIdMap.get(globalFarId);
    }

    // NOTE: FarIdMapListener is run on the same thread intentionally in order to ensure that
    //       reverseFarIdMap update always finishes right after farIdMap is updated
    private class FarIdMapListener implements MapEventListener<UpfRuleIdentifier, Integer> {
        @Override
        public void event(MapEvent<UpfRuleIdentifier, Integer> event) {
            switch (event.type()) {
                case INSERT:
                    reverseFarIdMap.put(event.newValue().value(), event.key());
                    break;
                case UPDATE:
                    reverseFarIdMap.remove(event.oldValue().value());
                    reverseFarIdMap.put(event.newValue().value(), event.key());
                    break;
                case REMOVE:
                    reverseFarIdMap.remove(event.oldValue().value());
                    break;
                default:
                    break;
            }
        }
    }
}
