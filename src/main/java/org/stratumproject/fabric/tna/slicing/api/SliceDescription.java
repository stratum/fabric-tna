// Copyright 2022-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package org.stratumproject.fabric.tna.slicing.api;

import com.google.common.base.MoreObjects;
import com.google.common.base.Objects;
import com.google.common.collect.ImmutableMap;

import java.util.Collection;
import java.util.Map;

/**
 * Describes a slice.
 */
public class SliceDescription {

    private final SliceId id;
    private final String name;
    private final ImmutableMap<TrafficClass, TrafficClassDescription> tcDescrs;

    /**
     * Creates a new slice description.
     *
     * @param id       slice ID
     * @param name     name
     * @param tcDescrs traffic class descriptions
     */
    public SliceDescription(SliceId id, String name,
                            Map<TrafficClass, TrafficClassDescription> tcDescrs) {
        this.id = id;
        this.tcDescrs = ImmutableMap.copyOf(tcDescrs);
        this.name = name;
    }

    /**
     * Returns the slice ID.
     *
     * @return slice ID
     */
    public SliceId id() {
        return id;
    }

    /**
     * Returns the descriptions of the traffic classes within this slice.
     *
     * @return traffic class descriptions
     */
    public Collection<TrafficClassDescription> tcDescriptions() {
        return tcDescrs.values();
    }

    /**
     * Returns the description for the given traffic class.
     *
     * @param tc traffic class
     * @return traffic class description
     */
    public TrafficClassDescription tcDescription(TrafficClass tc) {
        return tcDescrs.get(tc);
    }

    /**
     * Returns the name of this slice.
     *
     * @return slice name
     */
    public String name() {
        return name;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        SliceDescription that = (SliceDescription) o;
        return Objects.equal(id, that.id) &&
                Objects.equal(name, that.name) &&
                Objects.equal(tcDescrs, that.tcDescrs);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(id, name, tcDescrs);
    }

    @Override
    public String toString() {
        return MoreObjects.toStringHelper(this)
                .add("id", id)
                .add("name", name)
                .add("tcs", tcDescrs)
                .toString();
    }
}
