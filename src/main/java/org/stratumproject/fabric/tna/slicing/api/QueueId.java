// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.slicing.api;

import org.onlab.util.Identifier;

import static com.google.common.base.Preconditions.checkArgument;
import static org.stratumproject.fabric.tna.behaviour.Constants.QUEUE_ID_BEST_EFFORT;
import static org.stratumproject.fabric.tna.behaviour.Constants.QUEUE_ID_CONTROL;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.HDR_EGRESS_QID_BITWIDTH;

/**
 * Queue Identifier.
 */
public final class QueueId extends Identifier<Integer> {
    public static final Integer MAX = 1 << HDR_EGRESS_QID_BITWIDTH - 1;
    public static final QueueId BEST_EFFORT = QueueId.of(QUEUE_ID_BEST_EFFORT);
    public static final QueueId SYSTEM = QueueId.of(QUEUE_ID_CONTROL);
    public static final QueueId CONTROL = QueueId.of(QUEUE_ID_CONTROL);

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
        checkArgument(id >= 0 && id <= MAX, "Invalid id %s. Valid range is from %s to %s", id, 0, MAX);
        return new QueueId(id);
    }
}
