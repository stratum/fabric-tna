// Copyright 2018-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-1.0

package org.stratumproject.fabric.tna.behaviour.pipeliner;

import org.onosproject.net.flowobjective.ObjectiveError;

/**
 * Signals an exception when translating a flow objective.
 */
class FabricPipelinerException extends Exception {

    private final ObjectiveError error;

    /**
     * Creates a new exception for the given message. Sets ObjectiveError to
     * UNSUPPORTED.
     *
     * @param message message
     */
    FabricPipelinerException(String message) {
        super(message);
        this.error = ObjectiveError.UNSUPPORTED;
    }

    /**
     * Creates a new exception for the given message and ObjectiveError.
     *
     * @param message message
     * @param error objective error
     */
    FabricPipelinerException(String message, ObjectiveError error) {
        super(message);
        this.error = error;
    }

    /**
     * Returns the ObjectiveError of this exception.
     *
     * @return objective error
     */
    ObjectiveError objectiveError() {
        return error;
    }
}
