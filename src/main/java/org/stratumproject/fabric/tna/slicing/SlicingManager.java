// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.slicing;

import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.store.service.ConsistentMap;
import org.stratumproject.fabric.tna.slicing.api.QueueId;
import org.stratumproject.fabric.tna.slicing.api.SliceId;
import org.stratumproject.fabric.tna.slicing.api.SlicingAdminService;
import org.stratumproject.fabric.tna.slicing.api.SlicingService;
import org.stratumproject.fabric.tna.slicing.api.TrafficClass;

import java.util.Map;
import java.util.Set;

/**
 * Implementation of SlicingService.
 */
public class SlicingManager implements SlicingService, SlicingAdminService {

    ConsistentMap<SliceId, Map<TrafficClass, QueueId>> slices;
    /*
     * SliceId -> (null) for available slices
     * SliceId -> {BEST_EFFORT -> m1, q1} for newly created slice
     * SliceId -> {BEST_EFFORT -> m1, q1, ELASTIC -> m2, q2} when adding elastic tc
     * Do not allow removing BEST_EFFORT TC
    */

    ConsistentMap<TrafficClass, Set<QueueId>> queues;
    /*
     * Available queue id for given TC.
     * Static for now. Dynamic later.
     *     ELASTIC -> [1, 2, 3]
     *     REAL_TIME -> [5, 6, 7]
     *     UNKNOWN -> [4, 8] (unallocated)
     * addQueue(ELASTIC, 4)
     *     ELASTIC -> [1, 2, 3, 4]
     *     REAL_TIME -> [5, 6, 7]
     *     UNKNOWN -> [8]
     * removeQueue(ELASTIC, 1)
     *     check if queue in use. need to use distributedLock with addTc, removeTc to make sure
     *     no one is using the queue while we are trying to remove
     *     synchronize is not good enough since other ONOS instance will access too (in multi UP4 setup)
     *     ELASTIC -> [2, 3, 4]
     *     REAL_TIME -> [5, 6, 7]
     *     UNKNOWN -> [2, 8]
    */

    // Implements SlicingService

    @Override
    public Set<SliceId> getSlices() {
        return null;
    }

    @Override
    public boolean addTrafficClass(SliceId sliceId, TrafficClass tc) {
        // TODO Admission control
        return false;
    }

    @Override
    public boolean removeTrafficClass(SliceId sliceId, TrafficClass tc) {
        return false;
    }

    @Override
    public Set<TrafficClass> getTrafficClasses(SliceId sliceId) {
        return null;
    }

    @Override
    public boolean addFlow(TrafficTreatment treatment, SliceId sliceId, TrafficClass tc) {
        // TODO Admission control
        return false;
    }

    @Override
    public boolean removeFlow(TrafficTreatment treatment, SliceId sliceId, TrafficClass tc) {
        return false;
    }

    @Override
    public Set<TrafficTreatment> getFlows(SliceId sliceId, TrafficClass tc) {
        return null;
    }

    // Implements SlicingAdminService

    @Override
    public boolean addSlice(SliceId sliceId) {
        return false;
    }

    @Override
    public boolean removeSlice(SliceId sliceId) {
        return false;
    }

    @Override
    public boolean reserveQueue(TrafficClass tc, QueueId queueId) {
        return false;
    }

    @Override
    public boolean releaseQueue(TrafficClass tc, QueueId queueId) {
        return false;
    }

    // TODO Expose REST API
}
