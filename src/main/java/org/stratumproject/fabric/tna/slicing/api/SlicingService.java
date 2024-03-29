// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0
package org.stratumproject.fabric.tna.slicing.api;

import org.onosproject.net.flow.TrafficSelector;

import java.util.Set;

/**
 * Service for network slicing and QoS.
 */
public interface SlicingService {

    /**
     * Gets all slice IDs.
     *
     * @return set of slice IDs
     */
    Set<SliceId> getSlices();

    /**
     * Gets all traffic classes in given slice.
     *
     * @param sliceId slice identifier
     * @return a set of traffic classes in given slice
     */
    Set<TrafficClass> getTrafficClasses(SliceId sliceId);

    /**
     * Sets a default traffic class that is applied to all unclassified traffic
     * of a slice. The implementation does not attempt to verify that the given
     * traffic class has been already allocated for the given slice. If not
     * allocated, the device is expected to forward traffic as best effort.
     *
     * @param sliceId slice identifier
     * @param tc traffic class
     * @return true if the default traffic class is set successfully, false otherwise.
     */
    boolean setDefaultTrafficClass(SliceId sliceId, TrafficClass tc);

    /**
     * Gets the default traffic class for a given slice.
     *
     * @param sliceId slice identifier
     * @return The default traffic class for the given slice
     */
    TrafficClass getDefaultTrafficClass(SliceId sliceId);

    /**
     * Resets the default traffic class to BEST_EFFORT, for all slices.
     */
    void resetDefaultTrafficClassForAllSlices();

    // TODO: get traffic class parameters

    /**
     * Associates flow identified by given selector with given slice ID and traffic class.
     *
     * @param selector flow identifier
     * @param sliceId slice identifier
     * @param tc traffic class
     * @return true if the flow is associated with given slice/tc successfully.
     * @throws SlicingException if an error occurred.
     */
    boolean addClassifierFlow(TrafficSelector selector, SliceId sliceId, TrafficClass tc);

    /**
     * Dissociates flow identified by given selector with given slice ID and traffic class.
     *
     * @param selector flow identifier
     * @param sliceId slice identifier
     * @param tc traffic class
     * @return true if the flow is dissociate with given slice/tc successfully.
     * @throws SlicingException if an error occurred.
     */
    boolean removeClassifierFlow(TrafficSelector selector, SliceId sliceId, TrafficClass tc);

    /**
     * Removes all classifier flows in the system.
     *
     * @throws SlicingException if an error occurred.
     */
    void removeAllClassifierFlows();

    /**
     * Gets all flows in given sliceId and traffic class.
     *
     * @param sliceId slice identifier
     * @param tc      traffic class
     * @return set of flow identifiers
     */
    Set<TrafficSelector> getClassifierFlows(SliceId sliceId, TrafficClass tc);

    /**
     * Returns the ID of the slice to be used for system traffic.
     *
     * @return slice ID
     */
    SliceId getSystemSlice();

    /**
     * Returns the traffic class within the system slice ({@link
     * #getSystemSlice()}) to be used for system traffic.
     *
     * @return traffic class description
     */
    TrafficClassDescription getSystemTrafficClass();
}
