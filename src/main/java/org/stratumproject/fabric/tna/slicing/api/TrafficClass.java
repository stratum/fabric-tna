// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0
package org.stratumproject.fabric.tna.slicing.api;

/**
 * Type of traffic class.
 */
public enum TrafficClass {
    BEST_EFFORT(0),
    CONTROL(1),
    REAL_TIME(2),
    ELASTIC(3);

    public final int intValue;

    TrafficClass(int intValue) {
        this.intValue = intValue;
    }

    /**
     * Returns an integer uniquely identifying this traffic class. To be used in
     * flow programming, e.g., when writing the TC in packet headers and
     * metadata.
     *
     * @return TC integer value
     */
    public int toInt() {
        return intValue;
    }
}
