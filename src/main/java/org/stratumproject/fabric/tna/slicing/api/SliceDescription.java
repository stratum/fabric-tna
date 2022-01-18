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
    private final ImmutableMap<TrafficClass, TrafficClassDescription> tcDescriptions;

    public SliceDescription(SliceId id, String name, Map<TrafficClass, TrafficClassDescription> tcDescriptions) {
        this.id = id;
        this.tcDescriptions = ImmutableMap.copyOf(tcDescriptions);
        this.name = name;
    }

    public SliceId id() {
        return id;
    }

    public Collection<TrafficClassDescription> tcDescriptions() {
        return tcDescriptions.values();
    }

    public TrafficClassDescription tcDescription(TrafficClass tc) {
        return tcDescriptions.get(tc);
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
                Objects.equal(tcDescriptions, that.tcDescriptions);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(id, name, tcDescriptions);
    }

    @Override
    public String toString() {
        return MoreObjects.toStringHelper(this)
                .add("id", id)
                .add("name", name)
                .add("tcs", tcDescriptions)
                .toString();
    }

    // TODO: builder
}
