// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.slicing.api;

/**
 * Service through which slicing providers can inject information.
 */
public interface SlicingProviderService {

    /**
     * Adds a slice with given ID.
     * Adding default slice is not allowed.
     *
     * @param sliceId slice identifier
     * @return true if the slice is added successfully.
     * @throws SlicingException if an error occurred.
     */
    boolean addSlice(SliceId sliceId);

    /**
     * Removes a slice with given ID.
     * Removing default slice is not allowed.
     *
     * @param sliceId slice identifier
     * @return true if the slice is removed successfully.
     * @throws SlicingException if an error occurred.
     */
    boolean removeSlice(SliceId sliceId);

    /**
     * Adds a traffic class to the given slice.
     *
     * @param sliceId slice identifier
     * @param tcDescription traffic class config
     * @return true if the traffic class is added to given slice successfully.
     * @throws SlicingException if an error occurred.
     */
    boolean addTrafficClass(SliceId sliceId, TrafficClassDescription tcDescription);

    /**
     * Removes a traffic class from given slice.
     *
     * @param sliceId slice identifier
     * @param tc traffic class
     * @return true if the traffic class is removed from given slice successfully.
     * @throws SlicingException if an error occurred.
     */
    boolean removeTrafficClass(SliceId sliceId, TrafficClass tc);
}
