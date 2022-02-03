// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0
package org.stratumproject.fabric.tna.slicing.api;

import com.google.common.base.MoreObjects;

import java.util.Objects;

/**
 * Slicing Exception.
 */
public class SlicingException extends RuntimeException {

    /**
     * Type of slicing exception.
     */
    public enum Type {
        /**
         * Signals failure while processing a request.
         */
        FAILED,

        /**
         * Signals an invalid request that cannot be processed.
         */
        INVALID,

        /**
         * Signals a valid but unsupported request that cannot be processed.
         */
        UNSUPPORTED
    }

    private final Type errorType;

    public SlicingException(Type type, String message) {
        super(message);
        errorType = type;
    }

    /**
     * Return the error type of this exception.
     *
     * @return error type
     */
    public Type type() {
        return errorType;
    }

    @Override
    public int hashCode() {
        return Objects.hash(this.getMessage(), errorType);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (!(obj instanceof SlicingException)) {
            return false;
        }
        SlicingException other = (SlicingException) obj;
        return other.getMessage().equals(this.getMessage()) &&
                other.errorType == this.errorType;
    }

    @Override
    public String toString() {
        return MoreObjects.toStringHelper(getClass())
                .add("type", errorType)
                .add("message", this.getMessage())
                .toString();
    }
}
