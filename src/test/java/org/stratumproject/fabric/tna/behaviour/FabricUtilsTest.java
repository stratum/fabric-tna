// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0

package org.stratumproject.fabric.tna.behaviour;

import com.google.common.collect.ImmutableMap;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;
import org.junit.Test;

import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.stratumproject.fabric.tna.behaviour.FabricUtils.sliceTcConcat;
import static org.stratumproject.fabric.tna.behaviour.FabricUtils.sliceTcSplit;

/**
 * Tests for FabricUtils.
 */
public class FabricUtilsTest {

    ImmutableMap<Integer, Pair<Integer, Integer>> sliceTcMap =
            ImmutableMap.<Integer, Pair<Integer, Integer>>builder()
                    .put(0b000000, ImmutablePair.of(0, 0))
                    .put(0b000001, ImmutablePair.of(0, 1))
                    .put(0b000010, ImmutablePair.of(0, 2))
                    .put(0b000011, ImmutablePair.of(0, 3))
                    .put(0b101100, ImmutablePair.of(11, 0))
                    .put(0b111100, ImmutablePair.of(15, 0))
                    .put(0b111101, ImmutablePair.of(15, 1))
                    .put(0b111110, ImmutablePair.of(15, 2))
                    .put(0b111111, ImmutablePair.of(15, 3))
                    .build();

    @Test
    public void testSliceTcConcat() {
        for (var entry : sliceTcMap.entrySet()) {
            int sliceTcConcat = entry.getKey();
            Pair<Integer, Integer> sliceTcSeprated = entry.getValue();
            assertThat(sliceTcConcat(sliceTcSeprated.getLeft(), sliceTcSeprated.getRight()), equalTo(sliceTcConcat));
        }
    }

    @Test
    public void testSliceTcSplit() {
        for (var entry : sliceTcMap.entrySet()) {
            int sliceTcConcat = entry.getKey();
            Pair<Integer, Integer> sliceTcSeprated = entry.getValue();
            assertThat(sliceTcSplit(sliceTcConcat), equalTo(sliceTcSeprated));
        }
    }
}