// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0

package org.stratumproject.fabric.tna.behaviour.traceable;

import com.google.common.collect.Lists;
import org.junit.Before;
import org.junit.Test;
import org.onosproject.TestApplicationId;
import org.onosproject.core.ApplicationId;
import org.onosproject.net.DataPlaneEntity;
import org.onosproject.net.behaviour.PipelineTraceable;
import org.onosproject.net.driver.Behaviour;
import org.onosproject.net.flow.DefaultFlowEntry;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowEntry;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.TableId;
import org.onosproject.net.pi.model.PiPipeconf;
import org.onosproject.net.pi.model.PiPipeconfId;
import org.onosproject.net.pi.model.PiPipelineInterpreter;
import org.onosproject.net.pi.model.PiPipelineModel;
import org.onosproject.net.pi.model.PiTableId;
import org.onosproject.net.pi.service.PiPipeconfService;
import org.stratumproject.fabric.tna.behaviour.FabricCapabilities;
import org.stratumproject.fabric.tna.behaviour.P4InfoConstants;

import java.io.InputStream;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

import static org.easymock.EasyMock.createNiceMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Tests for AbstractFabricPipelineTraceable.
 */
public class AbstractFabricPipelineTraceableTest extends PipelineTraceableTest {
    // Constants
    private static final ApplicationId APP_ID = TestApplicationId.create("AbstractFabricPipelineTraceableTest");
    private static final TableId TABLE_ID = PiTableId.of("foo");

    // Tests objects
    private PiPipeconf testPiPipeconf = new TestPiPipeconf();
    private PiPipelineModel pipelineModel;
    private FabricCapabilities testCapabilities = new FabricCapabilities(testPiPipeconf);

    private static final FlowRule FILTERING_RULE =  DefaultFlowRule.builder()
            .withPriority(1)
            .withSelector(DefaultTrafficSelector.emptySelector())
            .withTreatment(DefaultTrafficTreatment.emptyTreatment())
            .fromApp(APP_ID)
            .forDevice(DEVICE_ID)
            .makePermanent()
            .forTable(P4InfoConstants.FABRIC_INGRESS_FILTERING_INGRESS_PORT_VLAN)
            .build();
    private static final FlowEntry FILTERING_FLOW_ENTRY = new DefaultFlowEntry(FILTERING_RULE);
    private static final FlowRule FOO_RULE =  DefaultFlowRule.builder()
            .withPriority(1)
            .withSelector(DefaultTrafficSelector.emptySelector())
            .withTreatment(DefaultTrafficTreatment.emptyTreatment())
            .fromApp(APP_ID)
            .forDevice(DEVICE_ID)
            .makePermanent()
            .forTable(TABLE_ID)
            .build();
    private static final FlowEntry FOO_FLOW_ENTRY = new DefaultFlowEntry(FOO_RULE);

    @Before
    public void setup() {
        pipelineModel = createNiceMock(PiPipelineModel.class);
        pipeconfService = createNiceMock(PiPipeconfService.class);
        expect(pipeconfService.getPipeconf(DEVICE_ID)).andReturn(Optional.of(testPiPipeconf)).anyTimes();
        expect(pipelineModel.counter(P4InfoConstants.FABRIC_INGRESS_SPGW_PDR_COUNTER)).andReturn(
                Optional.empty());
        replay(pipeconfService);
        replay(pipelineModel);
    }

    /**
     * Tests get behavior emulating a driver that supports interpreter interface.
     */
    @Test
    public void testGetBehavior() {
        // Overarching behavior
        assertTrue(testDriverHandler.hasBehaviour(PipelineTraceable.class));
        // Internal state for the tests
        PipelineTraceable pipelineTraceable = testDriverHandler.behaviour(PipelineTraceable.class);
        assertNotNull(pipelineTraceable);

        // Test ingress behavior
        PiPipelineInterpreter piInterpreter = ((AbstractFabricPipelineTraceable) pipelineTraceable)
                .getBehavior(PiPipelineInterpreter.class);
        assertNotNull(piInterpreter);
    }

    /**
     * Test for get dataplane entity logic.
     */
    @Test
    public void testGetDataPlaneEntity() {
        List<DataPlaneEntity> entities = Lists.newArrayList(new DataPlaneEntity(FOO_FLOW_ENTRY),
                new DataPlaneEntity(FILTERING_FLOW_ENTRY));
        List<DataPlaneEntity> expectedEntities = Lists.newArrayList(new DataPlaneEntity(FILTERING_FLOW_ENTRY));
        PipelineTraceableFiltering traceableFiltering = new PipelineTraceableFiltering(testCapabilities,
                testPiPipeconf, null);
        assertEquals(expectedEntities, traceableFiltering.getDataPlaneEntity(entities));
    }


    // Test pipeconf class
    private class TestPiPipeconf implements PiPipeconf {

        @Override
        public PiPipeconfId id() {
            return null;
        }

        @Override
        public PiPipelineModel pipelineModel() {
            return pipelineModel;
        }

        @Override
        public long fingerprint() {
            return 0;
        }

        @Override
        public Collection<Class<? extends Behaviour>> behaviours() {
            return null;
        }

        @Override
        public Optional<Class<? extends Behaviour>> implementation(Class<? extends Behaviour> behaviour) {
            return Optional.empty();
        }

        @Override
        public boolean hasBehaviour(Class<? extends Behaviour> behaviourClass) {
            return false;
        }

        @Override
        public Optional<InputStream> extension(ExtensionType type) {
            return Optional.empty();
        }
    }

}
