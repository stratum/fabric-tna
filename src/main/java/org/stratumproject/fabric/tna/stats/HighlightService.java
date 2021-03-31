// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package org.stratumproject.fabric.tna.stats;

import org.onosproject.ui.topo.Mod;

import java.util.Set;

public interface HighlightService {
    /**
     * Add UI highlight.
     *
     * @param id id
     * @param name name
     * @param mod UI mod
     */
    void addHighlight(int id, String name, Mod mod);

    /**
     * Remove UI highlight.
     *
     * @param id id
     * @param name name
     * @param mod UI mod
     */
    // TODO Make id unique so we can remove solely based on id
    void removeHighlight(int id, String name, Mod mod);

    /**
     * Gets current highlight store entries.
     *
     * @return set of HighlightKey
     */
    Set<HighlightKey> getHighlights();
}
