// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package org.stratumproject.fabric.tna.inbandtelemetry;

import org.onosproject.net.driver.HandlerBehaviour;

public interface IntProgrammable extends HandlerBehaviour {
    /**
     * Initializes the pipeline, by installing required flow rules not relevant
     * to specific watchlist, report and event. Returns true if the operation
     * was successful, false otherwise.
     *
     * @return true if successful, false otherwise
     */
    boolean init();

    /**
     * Clean up any INT-related configuration from the device.
     *
     * @return true if successful, false otherwise
     */
    boolean cleanup();

    /**
     * Set up report-related configuration.
     *
     * @param config a configuration regarding to the collector
     * @return true if the objective is successfully added; false otherwise.
     */
    public boolean setUpIntConfig(IntReportConfig config);
}
