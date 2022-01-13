// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.slicing.api;

import org.stratumproject.fabric.tna.slicing.QueueStoreValue;
import org.stratumproject.fabric.tna.slicing.SliceStoreKey;

import java.util.Map;

/**
 * Admin Service for network slicing and QoS.
 * These API are meant for troubleshooting and should not be exposed to external users via REST API
 */
public interface SlicingAdminService {
    /**
     * Gets all entries in the slice store.
     *
     * @return map of slice store
     */
    Map<SliceStoreKey, TrafficClassConfig> getSliceStore();

    /**
     * Reserves a queue for the queue pool of given traffic class.
     *
     * @param queueId queue identifier
     * @param tc traffic class
     * @return true if the queue is successfully reserved to the queue pool of given TC
     */
    boolean reserveQueue(QueueId queueId, TrafficClass tc);

    /**
     * Releases a queue from the queue pool.
     *
     * @param queueId queue identifier
     * @return true if the queue is successfully released from the queue pool of given TC
     */
    boolean releaseQueue(QueueId queueId);

    /**
     * Gets all entries in the queue store.
     *
     * @return map of queue store
     */
    Map<QueueId, QueueStoreValue> getQueueStore();
}
