// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.slicing.api;

import org.onosproject.net.flow.TrafficSelector;

import java.util.Set;

/**
 * Service for network slicing and QoS.
 */
public interface SlicingService {

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
     * Gets all slice IDs.
     *
     * @return set of slice IDs
     */
    Set<SliceId> getSlices();

    /**
     * Adds a traffic class to given slice.
     * BEST_EFFORT traffic class must be added first.
     *
     * @param sliceId slice identifier
     * @param tc traffic class
     * @return true if the traffic class is added to given slice successfully.
     * @throws SlicingException if an error occurred.
     */
    boolean addTrafficClass(SliceId sliceId, TrafficClass tc);

    /**
     * Removes a traffic class from given slice.
     * BEST_EFFORT traffic class must be removed last.
     *
     * @param sliceId slice identifier
     * @param tc traffic class
     * @return true if the traffic class is removed from given slice successfully.
     * @throws SlicingException if an error occurred.
     */
    boolean removeTrafficClass(SliceId sliceId, TrafficClass tc);

    /**
     * Gets all traffic classes in given slice.
     *
     * @param sliceId slice identifier
     * @return a set of traffic classes in given slice
     */
    Set<TrafficClass> getTrafficClasses(SliceId sliceId);

    /**
     * Associates flow identified by given selector with given slice ID and traffic class.
     *
     * @param selector flow identifier
     * @param sliceId slice identifier
     * @param tc traffic class
     * @return true if the flow is associated with given slice/tc successfully.
     * @throws SlicingException if an error occurred.
     */
    boolean addFlow(TrafficSelector selector, SliceId sliceId, TrafficClass tc);

    /**
     * Dissociates flow identified by given selector with given slice ID and traffic class.
     *
     * @param selector flow identifier
     * @param sliceId slice identifier
     * @param tc traffic class
     * @return true if the flow is dissociate with given slice/tc successfully.
     * @throws SlicingException if an error occurred.
     */
    boolean removeFlow(TrafficSelector selector, SliceId sliceId, TrafficClass tc);

    /**
     * Gets all flows in given sliceId and traffic class.
     *
     * @param sliceId slice identifier
     * @param tc traffic class
     * @return set of flow identifiers
     */
    Set<TrafficSelector> getFlows(SliceId sliceId, TrafficClass tc);
}
