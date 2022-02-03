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
         * Error occured while processing the request.
         */
        FAILED("FAILED"),

        /**
         * The request is invalid.
         * e.g. Remove BEST_EFFORT from default slice.
         */
        INVALID("INVALID"),

        /**
         * The request is valid but not supported.
         * e.g. Passing a traffic selector with ethernet criteria while the match field currently supports 5-tuple only.
         */
        UNSUPPORTED("UNSUPPORTED");

        private String value;
        private Type(String key) {
            value = key;
        }

        public String toString() {
            return value;
        }
    }

    public SlicingException(Type type, String message) {
        super(message);
        errorType = type;
    }

    public final Type errorType;

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
        if (other.getMessage().equals(this.getMessage()) && other.errorType == this.errorType) {
            return true;
        }
        return false;
    }

    @Override
    public String toString() {
        return MoreObjects.toStringHelper(getClass())
                .add("type", errorType.value)
                .add("message", this.getMessage())
                .toString();
    }
}
