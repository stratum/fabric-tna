// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.slicing;

import com.google.common.base.MoreObjects;
import org.stratumproject.fabric.tna.slicing.api.SliceId;
import org.stratumproject.fabric.tna.slicing.api.TrafficClass;

import java.util.Objects;

/**
 * Value of queue store.
 */
public class SliceStoreKey implements Comparable<SliceStoreKey> {
    private SliceId sliceId;
    private TrafficClass tc;

    public SliceStoreKey(SliceId sliceId, TrafficClass tc) {
        this.sliceId = sliceId;
        this.tc = tc;
    }

    public SliceId sliceId() {
        return this.sliceId;
    }

    public TrafficClass trafficClass() {
        return this.tc;
    }

    public SliceStoreKey setSliceId(SliceId sliceId) {
        this.sliceId = sliceId;
        return this;
    }

    public SliceStoreKey setTrafficClass(TrafficClass tc) {
        this.tc = tc;
        return this;
    }

    @Override
    public int compareTo(SliceStoreKey other) {
        return this.sliceId.id() - other.sliceId().id();
    }

    @Override
    public boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof SliceStoreKey)) {
            return false;
        }
        final SliceStoreKey other = (SliceStoreKey) obj;
        return Objects.equals(this.sliceId, other.sliceId) &&
                this.tc == other.tc;
    }

    @Override
    public int hashCode() {
        return Objects.hash(sliceId, tc);
    }

    @Override
    public String toString() {
        return MoreObjects.toStringHelper(getClass())
                .add("sliceId", sliceId)
                .add("trafficClass", tc)
                .toString();
    }
}
