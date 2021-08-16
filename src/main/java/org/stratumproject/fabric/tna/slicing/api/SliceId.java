// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.slicing.api;

import org.onlab.util.Identifier;

import static com.google.common.base.Preconditions.checkArgument;
import static org.stratumproject.fabric.tna.behaviour.Constants.MAX_SLICE_ID;

/**
 * Slice Identifier.
 */
public final class SliceId extends Identifier<Integer> {
    public static final Integer MAX = MAX_SLICE_ID;

    private SliceId(int id) {
        super(id);
    }

    /**
     * Constructs a SliceId instance.
     *
     * @param id slice identifier
     * @return SliceId instance
     * @throws IllegalArgumentException if given id is invalid
     */
    public static SliceId of(int id) {
        checkArgument(id >= 0 && id <= MAX, "Invalid id %d. Valid range is from %d to %d", id, 0, MAX);
        return new SliceId(id);
    }
}
