// Copyright 2022-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package org.stratumproject.fabric.tna.slicing;

import com.google.common.collect.Maps;
import org.easymock.EasyMock;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.core.DefaultApplicationId;
import org.onosproject.net.config.Config;
import org.onosproject.net.config.ConfigException;
import org.onosproject.net.config.NetworkConfigEvent;
import org.onosproject.net.config.NetworkConfigListener;
import org.onosproject.net.config.NetworkConfigRegistry;
import org.onosproject.net.config.NetworkConfigRegistryAdapter;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.intent.WorkPartitionService;
import org.stratumproject.fabric.tna.slicing.api.SliceId;
import org.stratumproject.fabric.tna.slicing.api.SlicingConfig;
import org.stratumproject.fabric.tna.slicing.api.SlicingProviderService;
import org.stratumproject.fabric.tna.slicing.api.SlicingService;
import org.stratumproject.fabric.tna.slicing.api.TrafficClass;
import org.stratumproject.fabric.tna.slicing.api.TrafficClassDescription;
import org.stratumproject.fabric.tna.utils.TestUtils;

import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.onlab.junit.TestTools.assertAfter;
import static org.onosproject.net.config.NetworkConfigEvent.Type.CONFIG_ADDED;
import static org.onosproject.net.config.NetworkConfigEvent.Type.CONFIG_REMOVED;

/**
 * Tests for NetcfgSlicingProvider.
 */
public class NetcfgSlicingProviderTest {

    private static final ApplicationId APP_ID = new DefaultApplicationId(0, "");
    private static final SlicingConfig SLICING_CONFIG = TestUtils.getSlicingConfig(APP_ID, "/slicing.json");
    private static final NetworkConfigEvent ADD_EVENT = new NetworkConfigEvent(
            CONFIG_ADDED, null, SLICING_CONFIG, null, SlicingConfig.class);
    private static final NetworkConfigEvent REMOVE_EVENT = new NetworkConfigEvent(
            CONFIG_REMOVED, null, null, SLICING_CONFIG, SlicingConfig.class);

    private NetcfgSlicingProvider provider;

    private Map<SliceId, Map<TrafficClass, TrafficClassDescription>> sliceStore;
    private NetworkConfigListener configListener;
    private SlicingConfig initialConfig;

    private final CoreService coreService = EasyMock.createMock(CoreService.class);
    private final SlicingService slicingService = new MockSlicingService();
    private final SlicingProviderService slicingProviderService = new MockSlicingProviderService();
    private final NetworkConfigRegistry netcfgRegistry = new MockNetworkConfigRegistry();
    private final WorkPartitionService workPartitionService = EasyMock.createMock(WorkPartitionService.class);

    @Rule
    public ExpectedException exceptionRule = ExpectedException.none();

    @Before
    public void setUp() throws Exception {
        provider = new NetcfgSlicingProvider();
        provider.coreService = coreService;
        provider.slicingService = slicingService;
        provider.slicingProviderService = slicingProviderService;
        provider.netcfgRegistry = netcfgRegistry;
        provider.workPartitionService = workPartitionService;

        // Populated by MockSlicingProviderService.
        sliceStore = Maps.newHashMap();
        // The default slice is always pre-provisioned.
        slicingProviderService.addSlice(SliceId.DEFAULT);

        EasyMock.expect(coreService.getAppId(EasyMock.anyString()))
                .andReturn(APP_ID).anyTimes();
        EasyMock.expect(workPartitionService.isMine(EasyMock.anyString(), EasyMock.anyObject()))
                .andReturn(true).anyTimes();

        EasyMock.replay(coreService, workPartitionService);
    }

    @Test
    public void testActivateWithoutInitialConfig() {
        initialConfig = null;
        provider.activate();
        EasyMock.verify(coreService, workPartitionService);
        // Initial config is handled asynchronously.
        assertAfter(50, this::assertStoreIsEmpty);
    }

    @Test
    public void testActivateWithInitialConfig() {
        initialConfig = SLICING_CONFIG;
        provider.activate();
        EasyMock.verify(coreService, workPartitionService);
        assertAfter(50, () -> assertStoreContainsConfig(SLICING_CONFIG));
    }

    @Test
    public void testEventAdd() {
        testActivateWithoutInitialConfig();
        assertTrue(configListener.isRelevant(ADD_EVENT));
        configListener.event(ADD_EVENT);
        assertAfter(50, () -> assertStoreContainsConfig(SLICING_CONFIG));
    }

    @Test
    public void testEventRemove() {
        testActivateWithInitialConfig();
        assertTrue(configListener.isRelevant(REMOVE_EVENT));
        configListener.event(REMOVE_EVENT);
        assertAfter(50, this::assertStoreIsEmpty);
    }

    @Test
    public void testDeactivate() {
        testActivateWithoutInitialConfig();
        provider.deactivate();
        // Events should be ignored.
        assertAfter(50, this::assertStoreIsEmpty);
    }

    private class MockNetworkConfigRegistry extends NetworkConfigRegistryAdapter {
        @Override
        public void addListener(NetworkConfigListener listener) {
            configListener = listener;
        }

        @Override
        public <S, C extends Config<S>> C getConfig(S subject, Class<C> configClass) {
            if (subject.equals(APP_ID) && configClass.equals(SlicingConfig.class)) {
                return (C) initialConfig;
            }
            return null;
        }
    }

    private void assertStoreIsEmpty() {
        // Only the pre-provisioned default slice is admitted.
        assertEquals(1, sliceStore.size());
        assertTrue(sliceStore.containsKey(SliceId.DEFAULT));
    }

    private void assertStoreContainsConfig(SlicingConfig config) {
        var expectedEntryCount = 0;
        try {
            for (var sliceDescr : config.slices()) {
                assertTrue(sliceStore.containsKey(sliceDescr.id()));
                for (var tcDescr : sliceDescr.tcDescriptions()) {
                    assertTrue(sliceStore.get(sliceDescr.id()).containsKey(tcDescr.trafficClass()));
                    assertEquals(tcDescr, sliceStore.get(sliceDescr.id()).get(tcDescr.trafficClass()));
                    expectedEntryCount++;
                }
            }
        } catch (ConfigException e) {
            fail(e.getMessage());
        }
        // Verify that we only added entries from the initial config.
        var actualEntryCount = sliceStore.values().stream().mapToLong(Map::size).sum();
        assertEquals(expectedEntryCount, actualEntryCount);
    }


    private class MockSlicingService implements SlicingService {

        @Override
        public Set<SliceId> getSlices() {
            return sliceStore.keySet();
        }

        @Override
        public Set<TrafficClass> getTrafficClasses(SliceId sliceId) {
            if (!sliceStore.containsKey(sliceId)) {
                return Collections.emptySet();
            }
            return sliceStore.get(sliceId).values().stream()
                    .map(TrafficClassDescription::trafficClass)
                    .collect(Collectors.toSet());
        }

        @Override
        public boolean setDefaultTrafficClass(SliceId sliceId, TrafficClass tc) {
            return false;
        }

        @Override
        public TrafficClass getDefaultTrafficClass(SliceId sliceId) {
            return null;
        }

        @Override
        public boolean addClassifierFlow(TrafficSelector selector, SliceId sliceId, TrafficClass tc) {
            return false;
        }

        @Override
        public boolean removeClassifierFlow(TrafficSelector selector, SliceId sliceId, TrafficClass tc) {
            return false;
        }

        @Override
        public Set<TrafficSelector> getClassifierFlows(SliceId sliceId, TrafficClass tc) {
            return null;
        }

        @Override
        public SliceId getSystemSlice() {
            return null;
        }

        @Override
        public TrafficClassDescription getSystemTrafficClass() {
            return null;
        }
    }

    private class MockSlicingProviderService implements SlicingProviderService {

        @Override
        public boolean addSlice(SliceId sliceId) {
            sliceStore.putIfAbsent(sliceId, Maps.newHashMap());
            return true;
        }

        @Override
        public boolean removeSlice(SliceId sliceId) {
            sliceStore.remove(sliceId);
            return true;
        }

        @Override
        public boolean addTrafficClass(SliceId sliceId, TrafficClassDescription tcDescription) {
            sliceStore.get(sliceId).put(tcDescription.trafficClass(), tcDescription);
            return true;
        }

        @Override
        public boolean removeTrafficClass(SliceId sliceId, TrafficClass tc) {
            sliceStore.get(sliceId).remove(tc);
            return false;
        }
    }

}