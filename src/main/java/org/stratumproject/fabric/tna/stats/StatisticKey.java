// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.stats;

import com.google.common.base.MoreObjects;
import org.onosproject.net.flow.TrafficSelector;

import java.util.Objects;

public final class StatisticKey {
    private TrafficSelector selector;
    private int id;

    private StatisticKey() {
        // Private constructor
    }

    public TrafficSelector selector() {
        return selector;
    }

    public int id() {
        return id;
    }

    public static Builder builder() {
        return new Builder();
    }

    @Override
    public boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof StatisticKey)) {
            return false;
        }
        final StatisticKey other = (StatisticKey) obj;
        return Objects.equals(this.selector, other.selector) &&
                this.id == other.id;
    }

    @Override
    public int hashCode() {
        return Objects.hash(selector, id);
    }

    @Override
    public String toString() {
        return MoreObjects.toStringHelper(getClass())
                .add("selector", selector)
                .add("id", id)
                .toString();
    }

    public static class Builder {
        private StatisticKey key = new StatisticKey();

        public Builder withSelector(TrafficSelector selector) {
            key.selector = selector;
            return this;
        }

        public Builder withId(int id) {
            key.id = id;
            return this;
        }

        public StatisticKey build() {
            return key;
        }
    }
}
