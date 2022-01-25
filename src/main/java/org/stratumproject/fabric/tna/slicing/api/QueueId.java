// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.slicing.api;

import org.onlab.util.Identifier;

import static com.google.common.base.Preconditions.checkArgument;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.HDR_EGRESS_QID_BITWIDTH;

/**
 * Queue identifier.
 */
public final class QueueId extends Identifier<Integer> implements Comparable<QueueId> {
    public static final QueueId ZERO = new QueueId(0);
    public static final QueueId BEST_EFFORT = ZERO;
    public static final int MIN = 1;
    public static final int MAX = (1 << HDR_EGRESS_QID_BITWIDTH) - 1;

    private QueueId(int id) {
        super(id);
    }

    /**
     * Constructs a QueueId instance.
     *
     * @param id queue identifier
     * @return QueueId instance
     * @throws IllegalArgumentException if given id is invalid
     */
    public static QueueId of(int id) {
        checkArgument(id >= MIN && id <= MAX, "Invalid id %s. Valid range is from %s to %s", id, MIN, MAX);
        return new QueueId(id);
    }

    @Override
    public int compareTo(QueueId other) {
        return this.id() - other.id();
    }
}
