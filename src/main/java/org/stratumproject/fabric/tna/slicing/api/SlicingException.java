// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.slicing.api;

/**
 * Slicing Exception.
 */
public class SlicingException extends RuntimeException {
    /**
     * Type of slicing exception.
     */
    public enum ErrorType {
        FAILED("FAILED"),
        INVALID("INVALID"),
        UNSUPPORTED("UNSUPPORTED");

        private String value;
        private ErrorType(String key) {
            value = key;
        }

        public String toString() {
            return value;
        }
    }

    public SlicingException(ErrorType type, String message) {
        super(message);
        errorType = type;
    }

    public ErrorType errorType;
}
