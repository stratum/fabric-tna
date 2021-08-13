// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.slicing;

import com.google.common.base.MoreObjects;
import org.stratumproject.fabric.tna.slicing.api.TrafficClass;

import java.util.Objects;

/**
 * Value of queue store.
 */
public class QueueStoreValue {
    private TrafficClass tc;
    private boolean available;

    public QueueStoreValue(TrafficClass tc, boolean available) {
        this.tc = tc;
        this.available = available;
    }

    public TrafficClass trafficClass() {
        return this.tc;
    }

    public QueueStoreValue setTrafficClass(TrafficClass tc) {
        this.tc = tc;
        return this;
    }

    public boolean available() {
        return this.available;
    }

    public QueueStoreValue setAvailable(boolean available) {
        this.available = available;
        return this;
    }

    @Override
    public boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof QueueStoreValue)) {
            return false;
        }
        final QueueStoreValue other = (QueueStoreValue) obj;
        return this.tc == other.tc &&
                this.available == other.available;
    }

    @Override
    public int hashCode() {
        return Objects.hash(tc, available);
    }

    @Override
    public String toString() {
        return MoreObjects.toStringHelper(getClass())
                .add("trafficClass", tc)
                .add("available", available)
                .toString();
    }
}
