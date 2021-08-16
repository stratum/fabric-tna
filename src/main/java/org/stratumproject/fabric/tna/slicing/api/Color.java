// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.slicing.api;

import static org.stratumproject.fabric.tna.behaviour.Constants.COLOR_GREEN;
import static org.stratumproject.fabric.tna.behaviour.Constants.COLOR_RED;
import static org.stratumproject.fabric.tna.behaviour.Constants.COLOR_YELLOW;

/**
 * Meter bucket color.
 */
public enum Color {
    GREEN(COLOR_GREEN),
    YELLOW(COLOR_YELLOW),
    RED(COLOR_RED);

    public final int color;

    Color(int color) {
        this.color = color;
    }
}
