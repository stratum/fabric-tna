// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.slicing.api;

/**
 * Admin service for network slicing and QoS.
 */
public interface SlicingAdminService {

    /**
     * Adds a slice with given ID.
     *
     * @param sliceId slice identifier
     * @return true if the slice is added successfully, false otherwise.
     */
    boolean addSlice(SliceId sliceId);

    /**
     * Removes a slice with given ID.
     *
     * @param sliceId slice identifier
     * @return true if the slice is removed successfully, false otherwise.
     */
    boolean removeSlice(SliceId sliceId);

    /**
     * Reserves a queue for the queue pool of given traffic class.
     *
     * @param tc traffic class
     * @param queueId queue identifier
     * @return true if the queue is successfully reserved to the queue pool of given TC
     */
    boolean reserveQueue(TrafficClass tc, QueueId queueId);

    /**
     * Releases a queue from the queue pool of given traffic class.
     *
     * @param tc traffic class
     * @param queueId queue identifier
     * @return true if the queue is successfully released from the queue pool of given TC
     */
    boolean releaseQueue(TrafficClass tc, QueueId queueId);

}
