// Copyright $today.year-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package org.stratumproject.fabric.tna.slicing.api;

import org.junit.Test;
import org.onosproject.TestApplicationId;
import org.onosproject.core.ApplicationId;
import org.stratumproject.fabric.tna.utils.TestUtils;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * Tests for SlicingConfig.
 */
public class SlicingConfigTest {

    private static final String APP_NAME = "foobar";
    private static final ApplicationId APP_ID = new TestApplicationId(APP_NAME);

    @Test
    public void testConstruction() throws Exception {
        SlicingConfig config = TestUtils.getSlicingConfig(APP_ID, "/slicing.json");

        assertTrue(config.isValid());

        assertEquals(QueueId.of(0), config.bestEffortQueueId());

        assertEquals(3, config.slices().size());
        assertNotNull(config.slice(SliceId.of(0)));
        assertNotNull(config.slice(SliceId.of(1)));
        assertNotNull(config.slice(SliceId.of(2)));
        assertNull(config.slice(SliceId.of(3)));

        SliceDescription sliceDescr;
        TrafficClassDescription tcDescr;

        sliceDescr = config.slice(SliceId.of(0));
        assertEquals(SliceId.of(0), sliceDescr.id());
        assertEquals("Default", sliceDescr.name());
        assertEquals(1, sliceDescr.tcConfigs().size());

        tcDescr = sliceDescr.tcConfig(TrafficClass.REAL_TIME);
        assertNotNull(tcDescr);
        assertEquals(QueueId.of(1), tcDescr.queueId());
        assertEquals(TrafficClassDescription.UNLIMITED_BPS, tcDescr.maxRateBps());
        assertEquals(0, tcDescr.gminRateBps());
        assertTrue(tcDescr.isSystemTc());

        sliceDescr = config.slice(SliceId.of(1));
        assertEquals(SliceId.of(1), sliceDescr.id());
        assertEquals("P4-UPF", sliceDescr.name());
        assertEquals(3, sliceDescr.tcConfigs().size());

        tcDescr = sliceDescr.tcConfig(TrafficClass.CONTROL);
        assertNotNull(tcDescr);
        assertEquals(QueueId.of(2), tcDescr.queueId());
        assertEquals(2000000, tcDescr.maxRateBps());
        assertEquals(0, tcDescr.gminRateBps());
        assertFalse(tcDescr.isSystemTc());

        tcDescr = sliceDescr.tcConfig(TrafficClass.REAL_TIME);
        assertNotNull(tcDescr);
        assertEquals(QueueId.of(3), tcDescr.queueId());
        assertEquals(50000000, tcDescr.maxRateBps());
        assertEquals(0, tcDescr.gminRateBps());
        assertFalse(tcDescr.isSystemTc());

        tcDescr = sliceDescr.tcConfig(TrafficClass.ELASTIC);
        assertNotNull(tcDescr);
        assertEquals(QueueId.of(4), tcDescr.queueId());
        assertEquals(TrafficClassDescription.UNLIMITED_BPS, tcDescr.maxRateBps());
        assertEquals(10000000, tcDescr.gminRateBps());
        assertFalse(tcDescr.isSystemTc());

        sliceDescr = config.slice(SliceId.of(2));
        assertEquals(SliceId.of(2), sliceDescr.id());
        assertEquals("BESS-UPF", sliceDescr.name());
        assertEquals(1, sliceDescr.tcConfigs().size());

        tcDescr = sliceDescr.tcConfig(TrafficClass.ELASTIC);
        assertNotNull(tcDescr);
        assertEquals(QueueId.of(5), tcDescr.queueId());
        assertEquals(TrafficClassDescription.UNLIMITED_BPS, tcDescr.maxRateBps());
        assertEquals(0, tcDescr.gminRateBps());
        assertFalse(tcDescr.isSystemTc());
    }
}