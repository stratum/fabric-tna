// Copyright $today.year-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package org.stratumproject.fabric.tna.slicing.api;

import com.google.common.base.MoreObjects;
import com.google.common.base.Objects;

/**
 * Describes an instance of a traffic class within a slice.
 */
public class TrafficClassDescription {

    public static final long UNLIMITED_BPS = Long.MAX_VALUE;

    // Common to all slices. No bandwidth guarantees or limitations.
    public static final TrafficClassDescription BEST_EFFORT = new TrafficClassDescription(
            TrafficClass.BEST_EFFORT, QueueId.BEST_EFFORT, UNLIMITED_BPS, 0, false);

    private final TrafficClass tc;
    private final QueueId qid;
    private final long maxRateBps;
    private final long gminRateBps;
    private final boolean isSystemTc;

    /**
     * Creates a new traffic class description.
     *
     * @param tc          traffic class enum value
     * @param qid         queue ID
     * @param maxRateBps  maximum bitrate in bps
     * @param gminRateBps guaranteed minimum rate in bps
     * @param isSystemTc  whether this traffic class is to be used for system traffic
     */
    public TrafficClassDescription(TrafficClass tc, QueueId qid, long maxRateBps,
                                   long gminRateBps, boolean isSystemTc) {
        this.tc = tc;
        this.qid = qid;
        this.maxRateBps = maxRateBps;
        this.gminRateBps = gminRateBps;
        this.isSystemTc = isSystemTc;
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
    public long getMaxRateBps() {
        return maxRateBps;
    }

    /**
     * Returns true if this traffic class is not rate limited, false otherwise.
     *
     * @return true if rate is unlimited
     */
    public boolean isMaxRateUnlimited() {
        return maxRateBps == UNLIMITED_BPS;
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
    public long getGminRateBps() {
        return gminRateBps;
    }

    /**
     * Returns true if this class is expected to carry system traffic.
     *
     * @return true if this is the system traffic class
     */
    public boolean isSystemTc() {
        return isSystemTc;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        TrafficClassDescription that = (TrafficClassDescription) o;
        return maxRateBps == that.maxRateBps &&
                gminRateBps == that.gminRateBps &&
                isSystemTc == that.isSystemTc &&
                tc == that.tc &&
                Objects.equal(qid, that.qid);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(tc, qid, maxRateBps, gminRateBps, isSystemTc);
    }

    @Override
    public String toString() {
        return MoreObjects.toStringHelper(this)
                .add("tc", tc)
                .add("qid", qid)
                .add("maxRateBps", maxRateBps)
                .add("gminRateBps", gminRateBps)
                .add("isSystemTc", isSystemTc)
                .toString();
    }

    // TODO: builder
}
