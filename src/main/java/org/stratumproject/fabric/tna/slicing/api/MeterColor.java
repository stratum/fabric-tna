// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0
package org.stratumproject.fabric.tna.slicing.api;

import static org.stratumproject.fabric.tna.Constants.COLOR_GREEN;
import static org.stratumproject.fabric.tna.Constants.COLOR_RED;
import static org.stratumproject.fabric.tna.Constants.COLOR_YELLOW;

/**
 * Meter bucket color.
 */
public enum MeterColor {
    GREEN(COLOR_GREEN),
    YELLOW(COLOR_YELLOW),
    RED(COLOR_RED);

    public final int intValue;

    MeterColor(int intValue) {
        this.intValue = intValue;
    }

    /**
     * Returns the integer value of this color to be used for flow programming.
     *
     * @return integer value
     */
    public int toInt() {
        return intValue;
    }
}
