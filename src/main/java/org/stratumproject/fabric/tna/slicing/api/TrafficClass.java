// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0
package org.stratumproject.fabric.tna.slicing.api;

import static com.google.common.base.Preconditions.checkArgument;
import static org.stratumproject.fabric.tna.Constants.MAX_TC;

/**
 * Type of traffic class.
 */
public enum TrafficClass {
    BEST_EFFORT(0),
    CONTROL(1),
    REAL_TIME(2),
    ELASTIC(3);

    public static final Integer MAX = MAX_TC;

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

    /**
     * Constructs a traffic class instance from the unique integer identifier.
     *
     * @param tcId traffic class integer unique identifier
     * @return TrafficClass instance
     * @throws IllegalArgumentException if given tc is invalid
     */
    public static TrafficClass fromInteger(int tcId) {
        checkArgument(tcId >= 0 && tcId <= MAX, "Invalid tc %s. Valid range is from %s to %s", tcId, 0, MAX);
        switch (tcId) {
            case 0:
                return BEST_EFFORT;
            case 1:
                return CONTROL;
            case 2:
                return REAL_TIME;
            case 3:
                return ELASTIC;
            default:
                // Should never reach this point
                throw new IllegalArgumentException("Invalid traffic class identifier");
        }
    }
}
