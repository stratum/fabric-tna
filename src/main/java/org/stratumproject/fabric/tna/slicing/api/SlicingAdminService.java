// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.slicing.api;

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
}
