// Copyright $today.year-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package org.stratumproject.fabric.tna.slicing.api;

import com.google.common.base.MoreObjects;

import java.util.Objects;

/**
 * Configuration of a traffic class.
 */
// TODO: complete javadocs
public class TrafficClassConfig {
    private static final int UNLIMITED_MAX_RATE = -1;

    public static final TrafficClassConfig BEST_EFFORT = new TrafficClassConfig(
            TrafficClass.BEST_EFFORT, QueueId.BEST_EFFORT, UNLIMITED_MAX_RATE, 0);

    private final TrafficClass tc;
    private final QueueId qid;
    private final int maxRateBps;
    private final int gminRateBps;

    public TrafficClassConfig(TrafficClass tc, QueueId qid, int maxRateBps, int gminRateBps) {
        this.tc = tc;
        this.qid = qid;
        this.maxRateBps = maxRateBps;
        this.gminRateBps = gminRateBps;
    }

    public TrafficClass trafficClass() {
        return tc;
    }

    public QueueId queueId() {
        return qid;
    }

    public int getMaxRateBps() {
        return maxRateBps;
    }

    public int getGminRateBps() {
        return gminRateBps;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TrafficClassConfig that = (TrafficClassConfig) o;
        return maxRateBps == that.maxRateBps &&
                gminRateBps == that.gminRateBps &&
                tc == that.tc &&
                Objects.equals(qid, that.qid);
    }

    @Override
    public int hashCode() {
        return Objects.hash(tc, qid, maxRateBps, gminRateBps);
    }

    @Override
    public String toString() {
        return MoreObjects.toStringHelper(this)
                .add("tc", tc)
                .add("qid", qid)
                .add("maxRateBps", maxRateBps)
                .add("gminRateBps", gminRateBps)
                .toString();
    }

    // TODO: builder
}
