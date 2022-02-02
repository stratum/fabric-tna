// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0
package org.stratumproject.fabric.tna.stats;

import com.google.common.base.MoreObjects;

import java.util.Objects;

/**
 * Data structure that contains the actual statistics result.
 */
public final class StatisticDataValue {
    /**
     * Current byte count.
     */
    private long byteCount;

    /**
     * Current packet count.
     */
    private long packetCount;

    /**
     * Last seen of the stat table flow.
     */
    private long timeMs;

    /**
     * Previous byte count from last stats collection.
     */
    private long prevByteCount;

    /**
     * Previous packet count from last stats collection.
     */
    private long prevPacketCount;

    /**
     * Previous Last seen of the stat table flow from last stats collection.
     */
    private long prevTimeMs;

    private StatisticDataValue() {
        // Private constructor
    }

    public long byteCount() {
        return byteCount;
    }

    public long packetCount() {
        return packetCount;
    }

    public long timeMs() {
        return timeMs;
    }

    public long prevByteCount() {
        return prevByteCount;
    }

    public long prevPacketCount() {
        return prevPacketCount;
    }

    public long prevTimeMs() {
        return prevTimeMs;
    }

    public long byteDiff() {
        return byteCount - prevByteCount;
    }

    public long packetDiff() {
        return packetCount - prevPacketCount;
    }

    public long timeMsDiff() {
        return timeMs - prevTimeMs;
    }

    public static Builder builder() {
        return new Builder();
    }

    @Override
    public boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof StatisticDataValue)) {
            return false;
        }
        final StatisticDataValue other = (StatisticDataValue) obj;
        return this.byteCount == other.byteCount &&
                this.packetCount == other.packetCount &&
                this.timeMs == other.timeMs &&
                this.prevByteCount == other.prevByteCount &&
                this.prevPacketCount == other.prevPacketCount &&
                this.prevTimeMs == other.prevTimeMs;
    }

    @Override
    public int hashCode() {
        return Objects.hash(byteCount, packetCount, prevByteCount, prevPacketCount, timeMs, prevTimeMs);
    }

    @Override
    public String toString() {
        return MoreObjects.toStringHelper(getClass())
                .add("byteCount", byteCount)
                .add("packetCount", packetCount)
                .add("prevByteCount", prevByteCount)
                .add("prevPacketCount", prevPacketCount)
                .add("timeMs", timeMs)
                .add("prevTimeMs", prevTimeMs)
                .toString();
    }

    public static class Builder {
        private StatisticDataValue data = new StatisticDataValue();

        public Builder withByteCount(long byteCount) {
            data.byteCount = byteCount;
            return this;
        }

        public Builder withPacketCount(long packetCount) {
            data.packetCount = packetCount;
            return this;
        }

        public Builder withPrevByteCount(long prevByteCount) {
            data.prevByteCount = prevByteCount;
            return this;
        }

        public Builder withPrevPacketCount(long prevPacketCount) {
            data.prevPacketCount = prevPacketCount;
            return this;
        }

        public Builder withTimeMs(long timeMs) {
            data.timeMs = timeMs;
            return this;
        }

        public Builder withPrevTimeMs(long prevTimeMs) {
            data.prevTimeMs = prevTimeMs;
            return this;
        }

        public StatisticDataValue build() {
            return data;
        }
    }
}
