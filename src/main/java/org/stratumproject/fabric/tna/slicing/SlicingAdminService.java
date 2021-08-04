// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.slicing;

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
     * Allocates given queue to a traffic class in given slice.
     *
     * @param tc traffic class
     * @param queueId queue identifier
     * @return true if the queue is successfully allocated to given slice and TC
     */
    boolean addQueue(TrafficClass tc, QueueId queueId);

    /**
     * Deallocates given queue from a traffic class in given slice.
     *
     * @param tc traffic class
     * @param queueId queue identifier
     * @return true if the queue is successfully deallocated from given slice and TC
     */
    boolean removeQueue(TrafficClass tc, QueueId queueId);

}
