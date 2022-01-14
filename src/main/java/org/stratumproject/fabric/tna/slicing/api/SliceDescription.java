// Copyright $today.year-present Open Networking Foundation
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
// TODO: javadoc
public class SliceDescription {

    private final SliceId id;
    private final String name;
    private final ImmutableMap<TrafficClass, TrafficClassDescription> tcConfigs;

    public SliceDescription(SliceId id, String name, Map<TrafficClass, TrafficClassDescription> tcConfigs) {
        this.id = id;
        this.tcConfigs = ImmutableMap.copyOf(tcConfigs);
        this.name = name;
    }

    public SliceId id() {
        return id;
    }

    public Collection<TrafficClassDescription> tcConfigs() {
        return tcConfigs.values();
    }

    public TrafficClassDescription tcConfig(TrafficClass tc) {
        return tcConfigs.get(tc);
    }

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
                Objects.equal(tcConfigs, that.tcConfigs);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(id, name, tcConfigs);
    }

    @Override
    public String toString() {
        return MoreObjects.toStringHelper(this)
                .add("id", id)
                .add("name", name)
                .add("tcConfigs", tcConfigs)
                .toString();
    }

    // TODO: builder
}
