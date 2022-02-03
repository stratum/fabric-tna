// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0

package org.stratumproject.fabric.tna.behaviour;

import org.junit.Test;

import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.stratumproject.fabric.tna.behaviour.FabricUtils.sliceTcConcat;

/**
 * Tests for FabricUtils.
 */
public class FabricUtilsTest {

    @Test
    public void testSliceTcConcat() {
        assertThat(sliceTcConcat(0, 0), equalTo(0b000000));
        assertThat(sliceTcConcat(0, 1), equalTo(0b000001));
        assertThat(sliceTcConcat(0, 2), equalTo(0b000010));
        assertThat(sliceTcConcat(0, 3), equalTo(0b000011));
        assertThat(sliceTcConcat(11, 0), equalTo(0b101100));
        assertThat(sliceTcConcat(15, 0), equalTo(0b111100));
        assertThat(sliceTcConcat(15, 1), equalTo(0b111101));
        assertThat(sliceTcConcat(15, 2), equalTo(0b111110));
        assertThat(sliceTcConcat(15, 3), equalTo(0b111111));
    }
}