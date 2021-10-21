// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.slicing.api;

import static org.stratumproject.fabric.tna.behaviour.Constants.COLOR_GREEN;
import static org.stratumproject.fabric.tna.behaviour.Constants.COLOR_RED;
import static org.stratumproject.fabric.tna.behaviour.Constants.COLOR_YELLOW;
import static org.stratumproject.fabric.tna.behaviour.Constants.BMV2_COLOR_RED;

/**
 * Meter bucket color.
 */
public enum Color {
    GREEN(COLOR_GREEN),
    YELLOW(COLOR_YELLOW),
    BMV2_RED(BMV2_COLOR_RED),
    RED(COLOR_RED);

    public final int color;

    Color(int color) {
        this.color = color;
    }
}
