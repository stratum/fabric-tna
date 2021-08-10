// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.slicing;

import org.onosproject.net.flow.TrafficTreatment;

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
     * Adds a traffic class to given slice.
     *
     * @param sliceId slice identifier
     * @param tc traffic class
     * @return true if the traffic class is added to given slice successfully, false otherwise.
     */
    boolean addTrafficClass(SliceId sliceId, TrafficClass tc);

    /**
     * Removes a traffic class from given slice.
     *
     * @param sliceId slice identifier
     * @param tc traffic class
     * @return true if the traffic class is removed from given slice successfully, false otherwise.
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
     * Associates flow identified by given treatment with given slice ID and traffic class.
     *
     * @param treatment flow identifier
     * @param sliceId slice identifier
     * @param tc traffic class
     * @return true if the flow is associated with given slice/tc successfully, false otherwise.
     */
    boolean addFlow(TrafficTreatment treatment, SliceId sliceId, TrafficClass tc);

    /**
     * Dissociates flow identified by given treatment with given slice ID and traffic class.
     *
     * @param treatment flow identifier
     * @param sliceId slice identifier
     * @param tc traffic class
     * @return true if the flow is dissociate with given slice/tc successfully, false otherwise.
     */
    boolean removeFlow(TrafficTreatment treatment, SliceId sliceId, TrafficClass tc);

    /**
     * Gets all flows in given sliceId and traffic class.
     *
     * @param sliceId slice identifier
     * @param tc traffic class
     * @return set of flow identifiers
     */
    Set<TrafficTreatment> getFlows(SliceId sliceId, TrafficClass tc);

    // TODO Consider bulk addition/removal in the future
}
