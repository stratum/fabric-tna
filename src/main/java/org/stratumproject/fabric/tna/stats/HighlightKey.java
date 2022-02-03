// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0

package org.stratumproject.fabric.tna.stats;

import com.google.common.base.MoreObjects;
import org.onosproject.ui.topo.Mod;

import java.util.Objects;

/**
 * Data structure to store all information related to a highlight.
 */
public final class HighlightKey {
    /**
     * Highlight ID.
     * Must be the same as monitor ID in StatisticService.
     */
    private int id;

    /**
     * Name of the highlight.
     * Could be arbitrary value.
     */
    private String name;

    /**
     * Highlight style.
     */
    private Mod mod;

    private HighlightKey() {
        // Private constructor
    }

    public int id() {
        return id;
    }

    public String name() {
        return name;
    }

    public Mod mod() {
        return mod;
    }

    public static Builder builder() {
        return new Builder();
    }

    @Override
    public boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof HighlightKey)) {
            return false;
        }
        final HighlightKey other = (HighlightKey) obj;
        return this.id == other.id &&
                Objects.equals(this.name, other.name) &&
                Objects.equals(this.mod, other.mod);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, name, mod);
    }

    @Override
    public String toString() {
        return MoreObjects.toStringHelper(getClass())
                .add("id", id)
                .add("name", name)
                .add("mod", mod)
                .toString();
    }

    public static class Builder {
        private HighlightKey key = new HighlightKey();

        public HighlightKey.Builder withId(int id) {
            key.id = id;
            return this;
        }

        public HighlightKey.Builder withName(String name) {
            key.name = name;
            return this;
        }

        public HighlightKey.Builder withMod(Mod mod) {
            key.mod = mod;
            return this;
        }

        public HighlightKey build() {
            return key;
        }
    }
}
