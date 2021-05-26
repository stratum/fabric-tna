// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.stats.cli;

import junit.framework.TestCase;
import org.easymock.EasyMock;
import org.onosproject.ui.topo.Mod;
import org.stratumproject.fabric.tna.stats.HighlightService;

public class HighlightAddCommandTest extends TestCase {
    private static final int ID = 1;
    private static final String NAME = "Traffic1";
    private static final String MOD = "style=\"stroke: #ff0000;\"";

    public void testDoExecute() {
        HighlightService service = EasyMock.createMock(HighlightService.class);
        service.addHighlight(ID, NAME, new Mod(MOD));
        EasyMock.expectLastCall().once();
        EasyMock.replay(service);

        HighlightAddCommand cmd = new HighlightAddCommand() {
            @Override
            public <T> T getService(Class<T> serviceClass) {
               return (T) service;
            }
        };
        cmd.id = ID;
        cmd.name = NAME;
        cmd.modStr = MOD;
        cmd.doExecute();

        EasyMock.verify(service);
    }
}
