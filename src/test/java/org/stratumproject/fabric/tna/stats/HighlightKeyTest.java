// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.stats;

import junit.framework.TestCase;
import org.onosproject.ui.topo.Mod;

import static org.junit.Assert.assertNotEquals;

public class HighlightKeyTest extends TestCase {
    private static final int ID_1 = 1;
    private static final int ID_2 = 2;
    private static final String NAME_1 = "Traffic1";
    private static final String NAME_2 = "Traffic2";
    private static final Mod MOD_1 = new Mod("style=\"stroke: #ff0000;\"");
    private static final Mod MOD_2 = new Mod("style=\"stroke: #0000ff;\"");

    public void testHightlightKey() {
        HighlightKey key1  = HighlightKey.builder()
                .withId(ID_1)
                .withName(NAME_1)
                .withMod(MOD_1)
                .build();
        HighlightKey key2  = HighlightKey.builder()
                .withId(ID_2)
                .withName(NAME_2)
                .withMod(MOD_2)
                .build();
        HighlightKey key3  = HighlightKey.builder()
                .withId(ID_1)
                .withName(NAME_1)
                .withMod(MOD_1)
                .build();

        assertEquals(key1.id(), ID_1);
        assertEquals(key1.name(), NAME_1);
        assertEquals(key1.mod(), MOD_1);

        assertEquals(key1, key3);
        assertNotEquals(key1, key2);
        assertEquals(key1.hashCode(), key3.hashCode());
        assertNotEquals(key1.hashCode(), key2.hashCode());
        assertEquals(key1.toString(), key3.toString());
        assertNotEquals(key1.toString(), key2.toString());
        assertEquals(key1, key1);
        assertNotEquals(key1, null);
    }
}
