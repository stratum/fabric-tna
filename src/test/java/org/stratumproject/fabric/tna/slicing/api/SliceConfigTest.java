// Copyright $today.year-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package org.stratumproject.fabric.tna.slicing.api;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.onosproject.TestApplicationId;
import org.onosproject.core.ApplicationId;
import org.onosproject.net.config.ConfigException;
import org.onosproject.net.config.InvalidFieldException;
import org.stratumproject.fabric.tna.utils.TestUtils;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * Tests for SlicingConfig.
 */
public class SliceConfigTest {

    @Rule
    public ExpectedException exceptionRule = ExpectedException.none();

    @Test
    public void testConstruction() throws Exception {
        SliceConfig config = TestUtils.getSlicingConfig(APP_ID, "/slicing.json");

        assertTrue(config.isValid());

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
        assertEquals(1, sliceDescr.tcDescriptions().size());

        tcDescr = sliceDescr.tcDescription(TrafficClass.REAL_TIME);
        assertNotNull(tcDescr);
        assertEquals(QueueId.of(1), tcDescr.queueId());
        assertEquals(TrafficClassDescription.UNLIMITED_BPS, tcDescr.maxRateBps());
        assertEquals(0, tcDescr.gminRateBps());
        assertTrue(tcDescr.isSystemTc());

        sliceDescr = config.slice(SliceId.of(1));
        assertEquals(SliceId.of(1), sliceDescr.id());
        assertEquals("P4-UPF", sliceDescr.name());
        assertEquals(3, sliceDescr.tcDescriptions().size());

        tcDescr = sliceDescr.tcDescription(TrafficClass.CONTROL);
        assertNotNull(tcDescr);
        assertEquals(QueueId.of(2), tcDescr.queueId());
        assertEquals(2000000, tcDescr.maxRateBps());
        assertEquals(0, tcDescr.gminRateBps());
        assertFalse(tcDescr.isSystemTc());

        tcDescr = sliceDescr.tcDescription(TrafficClass.REAL_TIME);
        assertNotNull(tcDescr);
        assertEquals(QueueId.of(3), tcDescr.queueId());
        assertEquals(50000000, tcDescr.maxRateBps());
        assertEquals(0, tcDescr.gminRateBps());
        assertFalse(tcDescr.isSystemTc());

        tcDescr = sliceDescr.tcDescription(TrafficClass.ELASTIC);
        assertNotNull(tcDescr);
        assertEquals(QueueId.of(4), tcDescr.queueId());
        assertEquals(TrafficClassDescription.UNLIMITED_BPS, tcDescr.maxRateBps());
        assertEquals(10000000, tcDescr.gminRateBps());
        assertFalse(tcDescr.isSystemTc());

        sliceDescr = config.slice(SliceId.of(2));
        assertEquals(SliceId.of(2), sliceDescr.id());
        assertEquals("BESS-UPF", sliceDescr.name());
        assertEquals(1, sliceDescr.tcDescriptions().size());

        tcDescr = sliceDescr.tcDescription(TrafficClass.ELASTIC);
        assertNotNull(tcDescr);
        assertEquals(QueueId.of(5), tcDescr.queueId());
        assertEquals(TrafficClassDescription.UNLIMITED_BPS, tcDescr.maxRateBps());
        assertEquals(0, tcDescr.gminRateBps());
        assertFalse(tcDescr.isSystemTc());
    }

    @Test
    public void testInvalidEmpty() {
        SliceConfig config = TestUtils.getSlicingConfig(APP_ID, "/slicing-invalid-empty.json");
        exceptionRule.expect(InvalidFieldException.class);
        exceptionRule.expectMessage("At least one slice should be specified");
        config.isValid();
    }


    @Test
    public void testInvalidMissingSystemTc() {
        SliceConfig config = TestUtils.getSlicingConfig(APP_ID, "/slicing-invalid-no-system-tc.json");
        exceptionRule.expect(InvalidFieldException.class);
        exceptionRule.expectMessage("At least one traffic class should be set as the system one");
        config.isValid();
    }

    @Test
    public void testInvalidTooManySystemTcs() {
        SliceConfig config = TestUtils.getSlicingConfig(APP_ID, "/slicing-invalid-too-many-system-tcs.json");
        exceptionRule.expect(InvalidFieldException.class);
        exceptionRule.expectMessage("Too many traffic classes are set as the system one");
        config.isValid();
    }

    @Test
    public void testInvalidTrafficClass() {
        SliceConfig config = TestUtils.getSlicingConfig(APP_ID, "/slicing-invalid-traffic-class.json");
        exceptionRule.expect(InvalidFieldException.class);
        exceptionRule.expectMessage("not a valid traffic class");
        config.isValid();
    }

    @Test
    public void testInvalidSliceId() {
        SliceConfig config = TestUtils.getSlicingConfig(APP_ID, "/slicing-invalid-slice-id.json");
        exceptionRule.expect(InvalidFieldException.class);
        exceptionRule.expectMessage("is not a valid slice ID");
        config.isValid();
    }

    @Test
    public void testInvalidBestEffortQueueId() {
        SliceConfig config = TestUtils.getSlicingConfig(APP_ID, "/slicing-invalid-best-effort.json");
        exceptionRule.expect(InvalidFieldException.class);
        exceptionRule.expectMessage("Field must be greater than 1");
        config.isValid();
    }

    @Test
    public void testInvalidBestEffortTcName() throws ConfigException {
        SliceConfig config = TestUtils.getSlicingConfig(APP_ID, "/slicing-invalid-best-effort.json");
        exceptionRule.expect(ConfigException.class);
        exceptionRule.expectMessage("BEST_EFFORT is implicit for all slices and cannot be configured");
        config.slice(SliceId.of(0));
    }

    @Test
    public void testInvalidQueueId() throws ConfigException {
        SliceConfig config = TestUtils.getSlicingConfig(APP_ID, "/slicing-invalid-queue-id.json");
        exceptionRule.expect(ConfigException.class);
        exceptionRule.expectMessage("is not a valid queue ID");
        config.slice(SliceId.of(0));
    }

    @Test
    public void testInvalidQueueIdMissing() throws ConfigException {
        SliceConfig config = TestUtils.getSlicingConfig(APP_ID, "/slicing-invalid-queue-id-missing.json");
        exceptionRule.expect(InvalidFieldException.class);
        exceptionRule.expectMessage("Field \"queueId\" is invalid: Mandatory field is not present");
        config.isValid();
    }
}
