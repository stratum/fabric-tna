// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.slicing.api;

import static org.stratumproject.fabric.tna.behaviour.Constants.TC_BEST_EFFORT;
import static org.stratumproject.fabric.tna.behaviour.Constants.TC_CONTROL;
import static org.stratumproject.fabric.tna.behaviour.Constants.TC_ELASTIC;
import static org.stratumproject.fabric.tna.behaviour.Constants.TC_REAL_TIME;

/**
 * Traffic Class.
 */
public enum TrafficClass {
    BEST_EFFORT(TC_BEST_EFFORT),
    CONTROL(TC_CONTROL),
    REAL_TIME(TC_REAL_TIME),
    ELASTIC(TC_ELASTIC),
    UNKNOWN(-1);

    public final int tc;

    TrafficClass(int tc) {
        this.tc = tc;
    }
}
