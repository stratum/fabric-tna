// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.stats.cli;

import junit.framework.TestCase;
import org.easymock.EasyMock;
import org.onosproject.ui.topo.Mod;
import org.stratumproject.fabric.tna.stats.HighlightKey;
import org.stratumproject.fabric.tna.stats.HighlightService;

import java.util.Set;

public class HighlightListCommandTest extends TestCase {
    private static final int ID = 1;
    private static final String NAME = "Traffic1";
    private static final String MOD = "style=\"stroke: #ff0000;\"";

    public void testDoExecute() {
        HighlightKey key = HighlightKey.builder()
                .withId(ID)
                .withName(NAME)
                .withMod(new Mod(MOD))
                .build();

        HighlightService service = EasyMock.createMock(HighlightService.class);
        EasyMock.expect(service.getHighlights()).andReturn(Set.of(key)).once();
        EasyMock.replay(service);

        HighlightListCommand cmd = new HighlightListCommand() {
            @Override
            public <T> T getService(Class<T> serviceClass) {
                return (T) service;
            }
        };
        cmd.doExecute();

        EasyMock.verify(service);
    }
}