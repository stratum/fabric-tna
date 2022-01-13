// Copyright $today.year-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package org.stratumproject.fabric.tna.slicing.api;

import com.google.common.base.MoreObjects;

import java.util.Objects;

/**
 * Describes the configuration of a traffic class within a slice.
 */
public class TrafficClassConfig {

    private static final int UNLIMITED_MAX_RATE = Integer.MAX_VALUE;

    // Common to all slices. No bandwidth guarantees or limitations.
    public static final TrafficClassConfig BEST_EFFORT = new TrafficClassConfig(
            TrafficClass.BEST_EFFORT, QueueId.BEST_EFFORT, UNLIMITED_MAX_RATE, 0);

    private final TrafficClass tc;
    private final QueueId qid;
    private final int maxRateBps;
    private final int gminRateBps;

    /**
     * Creates a new traffic class config.
     *
     * @param tc          traffic class enum value
     * @param qid         queue ID
     * @param maxRateBps  maximum bitrate in bps
     * @param gminRateBps guaranteed minimum rate in bps
     */
    public TrafficClassConfig(TrafficClass tc, QueueId qid, int maxRateBps, int gminRateBps) {
        this.tc = tc;
        this.qid = qid;
        this.maxRateBps = maxRateBps;
        this.gminRateBps = gminRateBps;
    }

    /**
     * Returns the traffic class.
     *
     * @return traffic class
     */
    public TrafficClass trafficClass() {
        return tc;
    }

    /**
     * Returns the queue ID associated to this traffic class.
     *
     * @return queue ID
     */
    public QueueId queueId() {
        return qid;
    }

    /**
     * Returns the maximum bitrate in bps. Sources sending at rates higher than
     * this might observe their traffic being shaped or policed. Meaningful only
     * if {@link #isMaxRateUnlimited()} is false.
     *
     * @return maximum bitrate in bps
     */
    public int getMaxRateBps() {
        return maxRateBps;
    }

    /**
     * Returns true if this traffic class is not rate limited, false otherwise.
     *
     * @return true if rate is unlimited
     */
    public boolean isMaxRateUnlimited() {
        return maxRateBps == UNLIMITED_MAX_RATE;
    }

    /**
     * Returns the guaranteed minimum bitrate in bps. Sources sending at rates
     * lower than this value can expect their traffic to be serviced without
     * limitations (drops or delay) at all times, even during congestion. {@code
     * getGminRateBps() == 0} signifies that data plane devices will not provide
     * any bandwidth guarantees.
     *
     * @return guaranteed minimum bitrate in bps
     */
    public int getGminRateBps() {
        return gminRateBps;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
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
