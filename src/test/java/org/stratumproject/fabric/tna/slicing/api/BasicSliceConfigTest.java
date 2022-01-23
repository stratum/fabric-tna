// Copyright $today.year-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package org.stratumproject.fabric.tna.slicing.api;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.onosproject.net.config.ConfigException;
import org.onosproject.net.config.InvalidFieldException;
import org.stratumproject.fabric.tna.utils.TestUtils;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Tests for SlicingConfig.
 */
public class BasicSliceConfigTest {

    private static final SliceId SLICE_ID = SliceId.of(1);

    @Rule
    public ExpectedException exceptionRule = ExpectedException.none();

    @Test
    public void testConstruction() throws Exception {
        BasicSliceConfig config = TestUtils.getSlicingConfig(SLICE_ID, "/slicing.json");

        assertTrue(config.isValid());

        assertEquals("foobar", config.name());
        assertEquals(3, config.tcDescriptions().size());

        TrafficClassDescription tcDescr;
        tcDescr = config.tcDescription(TrafficClass.CONTROL);
        assertNotNull(tcDescr);
        assertEquals(QueueId.of(1), tcDescr.queueId());
        assertEquals(2000000, tcDescr.maxRateBps());
        assertEquals(0, tcDescr.gminRateBps());
        assertTrue(tcDescr.isSystemTc());

        tcDescr = config.tcDescription(TrafficClass.REAL_TIME);
        assertNotNull(tcDescr);
        assertEquals(QueueId.of(2), tcDescr.queueId());
        assertEquals(50000000, tcDescr.maxRateBps());
        assertEquals(0, tcDescr.gminRateBps());
        assertFalse(tcDescr.isSystemTc());

        tcDescr = config.tcDescription(TrafficClass.ELASTIC);
        assertNotNull(tcDescr);
        assertEquals(QueueId.of(3), tcDescr.queueId());
        assertEquals(TrafficClassDescription.UNLIMITED_BPS, tcDescr.maxRateBps());
        assertEquals(10000000, tcDescr.gminRateBps());
        assertFalse(tcDescr.isSystemTc());
    }

    @Test
    public void testInvalidEmpty() {
        BasicSliceConfig config = TestUtils.getSlicingConfig(SLICE_ID, "/slicing-invalid-empty.json");
        exceptionRule.expect(InvalidFieldException.class);
        exceptionRule.expectMessage("Mandatory field is not present");
        config.isValid();
    }

    @Test
    public void testInvalidTrafficClass() {
        BasicSliceConfig config = TestUtils.getSlicingConfig(SLICE_ID, "/slicing-invalid-traffic-class.json");
        exceptionRule.expect(InvalidFieldException.class);
        exceptionRule.expectMessage("not a valid traffic class");
        config.isValid();
    }

    @Test
    public void testInvalidBestEffortQueueId() {
        BasicSliceConfig config = TestUtils.getSlicingConfig(SLICE_ID, "/slicing-invalid-best-effort.json");
        exceptionRule.expect(InvalidFieldException.class);
        exceptionRule.expectMessage("Field must be greater than 1");
        config.isValid();
    }

    @Test
    public void testInvalidBestEffortTcName() throws ConfigException {
        BasicSliceConfig config = TestUtils.getSlicingConfig(SLICE_ID, "/slicing-invalid-best-effort.json");
        exceptionRule.expect(ConfigException.class);
        exceptionRule.expectMessage("BEST_EFFORT is implicit for all slices and cannot be configured");
        config.tcDescriptions();
    }

    @Test
    public void testInvalidQueueId() throws ConfigException {
        BasicSliceConfig config = TestUtils.getSlicingConfig(SLICE_ID, "/slicing-invalid-queue-id.json");
        exceptionRule.expect(ConfigException.class);
        exceptionRule.expectMessage("is not a valid queue ID");
        config.tcDescriptions();
    }

    @Test
    public void testInvalidQueueIdMissing() throws ConfigException {
        BasicSliceConfig config = TestUtils.getSlicingConfig(SLICE_ID, "/slicing-invalid-queue-id-missing.json");
        exceptionRule.expect(InvalidFieldException.class);
        exceptionRule.expectMessage("Field \"queueId\" is invalid: Mandatory field is not present");
        config.isValid();
    }
}
