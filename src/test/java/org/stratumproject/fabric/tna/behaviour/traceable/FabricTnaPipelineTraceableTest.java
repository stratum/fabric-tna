// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0

package org.stratumproject.fabric.tna.behaviour.traceable;

import org.junit.Before;
import org.junit.Test;
import org.onosproject.net.DataPlaneEntity;
import org.onosproject.net.PipelineTraceableHitChain;
import org.onosproject.net.PipelineTraceableInput;
import org.onosproject.net.PipelineTraceableOutput;
import org.onosproject.net.PipelineTraceablePacket;
import org.onosproject.net.behaviour.PipelineTraceable;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.pi.model.PiPipeconf;
import org.onosproject.net.pi.service.PiPipeconfService;
import org.stratumproject.fabric.tna.PipeconfLoader;
import org.stratumproject.fabric.tna.behaviour.FabricCapabilities;

import java.net.URISyntaxException;
import java.util.List;
import java.util.Optional;

import static org.easymock.EasyMock.createNiceMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertThat;
import static org.stratumproject.fabric.tna.behaviour.traceable.PipelineTraceableTest.TraceableTest.ARP_UNTAG;
import static org.stratumproject.fabric.tna.behaviour.traceable.PipelineTraceableTest.TraceableTest.L2_BRIDG_UNTAG;
import static org.stratumproject.fabric.tna.behaviour.traceable.PipelineTraceableTest.TraceableTest.L2_BROAD_UNTAG;
import static org.stratumproject.fabric.tna.behaviour.traceable.PipelineTraceableTest.TraceableTest.L3_ECMP;
import static org.stratumproject.fabric.tna.behaviour.traceable.PipelineTraceableTest.TraceableTest.L3_UCAST_UNTAG;
import static org.stratumproject.fabric.tna.behaviour.traceable.PipelineTraceableTest.TraceableTest.MPLS_ECMP;
import static org.stratumproject.fabric.tna.behaviour.traceable.PipelineTraceableTest.TraceableTest.PUNT_IP;
import static org.stratumproject.fabric.tna.behaviour.traceable.PipelineTraceableTest.TraceableTest.PUNT_LLDP;
import static org.stratumproject.fabric.tna.behaviour.traceable.TraceableDataPlaneObjects.getDataPlaneEntities;
import static org.stratumproject.fabric.tna.behaviour.traceable.TraceableDataPlaneObjects.getHitChains;

/**
 * Tests for {@link FabricTnaPipelineTraceable}.
 */
public class FabricTnaPipelineTraceableTest extends PipelineTraceableTest {

    private PiPipeconf testPiPipeconf;

    @Before
    public void setUp() throws URISyntaxException {
        PipeconfLoader pipeconfLoader = new PipeconfLoader();
        // Pipeconf cannot be null
        testPiPipeconf = pipeconfLoader.buildAllTestPipeconfs()
                .stream()
                .findFirst()
                .orElse(null);
        assertNotNull("PiPipeconf is null", testPiPipeconf);

        // Mock pipeconf service
        pipeconfService = createNiceMock(PiPipeconfService.class);
        expect(pipeconfService.getPipeconf(DEVICE_ID)).andReturn(Optional.of(testPiPipeconf)).anyTimes();

        replay(pipeconfService);
    }

    // Init steps for the traceable
    private PipelineTraceable setupTraceable() {
        // Overarching behavior
        assertTrue(testDriverHandler.hasBehaviour(PipelineTraceable.class));
        // Internal state for the tests
        PipelineTraceable pipelineTraceable = testDriverHandler.behaviour(PipelineTraceable.class);
        assertNotNull(pipelineTraceable);
        pipelineTraceable.init();
        return pipelineTraceable;
    }

    // Builds up a traceable packet
    private PipelineTraceablePacket getPipelineTraceablePacket(TrafficSelector packet) {
        return new PipelineTraceablePacket(packet);
    }

    /**
     * Tests init for fabric-tna traceable.
     */
    @Test
    public void testInit() {
        PipelineTraceable pipelineTraceable = setupTraceable();

        // Verify the ingress pipeline
        List<PipelineTraceableCtrl> ingressPipeline = ((AbstractFabricPipelineTraceable) pipelineTraceable)
                .ingressPipeline;

        // Makes this test flexible to changes of the pipeconf
        FabricCapabilities fabricCapabilities = new FabricCapabilities(testPiPipeconf);
        if (fabricCapabilities.supportSpgw()) {
            assertThat(ingressPipeline.size(), is(5));
            assertTrue(ingressPipeline.get(0) instanceof PipelineTraceableSpgw);
            assertTrue(ingressPipeline.get(1) instanceof PipelineTraceableFiltering);
            assertTrue(ingressPipeline.get(2) instanceof PipelineTraceableForwarding);
            assertTrue(ingressPipeline.get(3) instanceof PipelineTraceableAcl);
            assertTrue(ingressPipeline.get(4) instanceof PipelineTraceableNext);
        } else {
            assertThat(ingressPipeline.size(), is(4));
            assertTrue(ingressPipeline.get(0) instanceof PipelineTraceableFiltering);
            assertTrue(ingressPipeline.get(1) instanceof PipelineTraceableForwarding);
            assertTrue(ingressPipeline.get(2) instanceof PipelineTraceableAcl);
            assertTrue(ingressPipeline.get(3) instanceof PipelineTraceableNext);
        }
    }

    /**
     * Test punt ip for fabric-tna traceable.
     */
    @Test
    public void testPuntIP() {
        PipelineTraceableInput pipelineInput = new PipelineTraceableInput(getPipelineTraceablePacket(
                IN_PUNT_IP_PACKET), DOWN_CP, getDataPlaneEntities(PUNT_IP));
        PipelineTraceable pipelineTraceable = setupTraceable();
        PipelineTraceableOutput pipelineOutput = pipelineTraceable.apply(pipelineInput);
        assertNotNull(pipelineOutput);

        assertThat(pipelineOutput.getHitChains().size(), is(1));
        assertThat(pipelineOutput.getResult(), is(PipelineTraceableOutput.PipelineTraceableResult.SUCCESS));

        PipelineTraceableHitChain hitChain = pipelineOutput.getHitChains().get(0);
        assertNotNull(hitChain);
        List<List<DataPlaneEntity>> chains = getHitChains(PUNT_IP);
        assertThat(chains.size(), is(1));

        // FIXME port is not null
        //assertNotNull(hitChain.getOutputPort());
        //assertThat(hitChain.getOutputPort().port(), is(PortNumber.CONTROLLER));
        assertNull(hitChain.getOutputPort());

        assertThat(hitChain.getHitChain().size(), is(4));

        assertEquals(IN_PUNT_IP_PACKET, hitChain.getEgressPacket().getPacket());
        assertEquals(PUNT_IP_METADATA, hitChain.getEgressPacket().getMetadata());
        assertFalse(hitChain.isDropped());
        assertEquals(chains.get(0), hitChain.getHitChain());
    }

    /**
     * Test arp for fabric-tna traceable.
     */
    @Test
    public void testArpUntag() {
        PipelineTraceableInput pipelineInput = new PipelineTraceableInput(new PipelineTraceablePacket(
                IN_ARP_PACKET), DOWN_CP, getDataPlaneEntities(ARP_UNTAG));
        PipelineTraceable pipelineTraceable = setupTraceable();
        PipelineTraceableOutput pipelineOutput = pipelineTraceable.apply(pipelineInput);
        assertNotNull(pipelineOutput);

        // FIXME number of hitchains depend on the number of the members of the VLAN domain
        assertThat(pipelineOutput.getHitChains().size(), is(1));
        assertThat(pipelineOutput.getResult(), is(PipelineTraceableOutput.PipelineTraceableResult.SUCCESS));

        // FIXME chains depend on the number of the members of the VLAN domain
        PipelineTraceableHitChain hitChain = pipelineOutput.getHitChains().get(0);
        assertNotNull(hitChain);
        List<List<DataPlaneEntity>> chains = getHitChains(ARP_UNTAG);
        assertThat(chains.size(), is(1));

        // FIXME port is not null
        //assertNotNull(hitChain.getOutputPort());
        //assertThat(hitChain.getOutputPort().port(), is(PortNumber.CONTROLLER));
        assertNull(hitChain.getOutputPort());

        // FIXME hit chain size is more than 5
        //assertThat(hitChain.getHitChain().size(), is(7));
        assertThat(hitChain.getHitChain().size(), is(5));

        assertEquals(IN_ARP_PACKET, hitChain.getEgressPacket().getPacket());
        assertEquals(ARP_METADATA, hitChain.getEgressPacket().getMetadata());
        assertFalse(hitChain.isDropped());
        assertEquals(chains.get(0), hitChain.getHitChain());
    }

    /**
     * Test punt lldp for fabric-tna traceable.
     */
    @Test
    public void testPuntLldp() {
        PipelineTraceableInput pipelineInput = new PipelineTraceableInput(new PipelineTraceablePacket(
                IN_PUNT_LLDP_PACKET), UP_CP, getDataPlaneEntities(PUNT_LLDP));
        PipelineTraceable pipelineTraceable = setupTraceable();
        PipelineTraceableOutput pipelineOutput = pipelineTraceable.apply(pipelineInput);
        assertNotNull(pipelineOutput);

        assertThat(pipelineOutput.getHitChains().size(), is(1));
        assertThat(pipelineOutput.getResult(), is(PipelineTraceableOutput.PipelineTraceableResult.SUCCESS));

        PipelineTraceableHitChain hitChain = pipelineOutput.getHitChains().get(0);
        assertNotNull(hitChain);
        List<List<DataPlaneEntity>> chains = getHitChains(PUNT_LLDP);
        assertThat(chains.size(), is(1));

        // FIXME port is not null
        //assertNotNull(hitChain.getOutputPort());
        //assertThat(hitChain.getOutputPort().port(), is(PortNumber.CONTROLLER));
        assertNull(hitChain.getOutputPort());

        assertThat(hitChain.getHitChain().size(), is(2));

        assertEquals(IN_PUNT_LLDP_PACKET, hitChain.getEgressPacket().getPacket());
        assertEquals(PUNT_LLDP_METADATA, hitChain.getEgressPacket().getMetadata());
        assertFalse(hitChain.isDropped());
        assertEquals(chains.get(0), hitChain.getHitChain());
    }

    /**
     * Test l2 bridging with untagged hosts for fabric-tna traceable.
     */
    @Test
    public void testL2BridingUntagged() {
        PipelineTraceableInput pipelineInput = new PipelineTraceableInput(new PipelineTraceablePacket(
                IN_L2_BRIDG_UNTAG_PACKET), DOWN_CP, getDataPlaneEntities(L2_BRIDG_UNTAG));
        PipelineTraceable pipelineTraceable = setupTraceable();
        PipelineTraceableOutput pipelineOutput = pipelineTraceable.apply(pipelineInput);
        assertNotNull(pipelineOutput);

        assertThat(pipelineOutput.getHitChains().size(), is(1));
        assertThat(pipelineOutput.getResult(), is(PipelineTraceableOutput.PipelineTraceableResult.SUCCESS));

        PipelineTraceableHitChain hitChain = pipelineOutput.getHitChains().get(0);
        assertNotNull(hitChain);
        List<List<DataPlaneEntity>> chains = getHitChains(L2_BRIDG_UNTAG);
        assertThat(chains.size(), is(1));

        // FIXME port is not null
        //assertNotNull(hitChain.getOutputPort());
        //assertThat(hitChain.getOutputPort().port(), is(PortNumber.CONTROLLER));
        assertNull(hitChain.getOutputPort());

        // FIXME hit chain is more than 4
        //assertThat(hitChain.getHitChain().size(), is(7));
        assertThat(hitChain.getHitChain().size(), is(4));

        assertEquals(IN_L2_BRIDG_UNTAG_PACKET, hitChain.getEgressPacket().getPacket());
        assertEquals(L2_BRIDG_UNTAG_METADATA, hitChain.getEgressPacket().getMetadata());
        assertFalse(hitChain.isDropped());
        assertEquals(chains.get(0), hitChain.getHitChain());
    }

    /**
     * Test l2 broadcast with untagged hosts for fabric-tna traceable.
     */
    @Test
    public void testL2BroadcastUntagged() {
        PipelineTraceableInput pipelineInput = new PipelineTraceableInput(new PipelineTraceablePacket(
                IN_L2_BROAD_UNTAG_PACKET), DOWN_CP, getDataPlaneEntities(L2_BROAD_UNTAG));
        PipelineTraceable pipelineTraceable = setupTraceable();
        PipelineTraceableOutput pipelineOutput = pipelineTraceable.apply(pipelineInput);
        assertNotNull(pipelineOutput);

        assertThat(pipelineOutput.getHitChains().size(), is(1));
        assertThat(pipelineOutput.getResult(), is(PipelineTraceableOutput.PipelineTraceableResult.SUCCESS));

        // FIXME chains depend on the number of the members of the VLAN domain
        PipelineTraceableHitChain hitChain = pipelineOutput.getHitChains().get(0);
        assertNotNull(hitChain);
        List<List<DataPlaneEntity>> chains = getHitChains(L2_BROAD_UNTAG);
        assertThat(chains.size(), is(1));

        // FIXME port is not null
        //assertNotNull(hitChain.getOutputPort());
        //assertThat(hitChain.getOutputPort().port(), is(PortNumber.CONTROLLER));
        assertNull(hitChain.getOutputPort());

        // FIXME hit chain is more than 4
        //assertThat(hitChain.getHitChain().size(), is(7));
        assertThat(hitChain.getHitChain().size(), is(4));

        assertEquals(IN_L2_BROAD_UNTAG_PACKET, hitChain.getEgressPacket().getPacket());
        assertEquals(L2_BROAD_UNTAG_METADATA, hitChain.getEgressPacket().getMetadata());
        assertFalse(hitChain.isDropped());
        assertEquals(chains.get(0), hitChain.getHitChain());
    }

    /**
     * Test l3 unicast routing for fabric-tna traceable.
     */
    @Test
    public void testL3Unicast() {
        PipelineTraceableInput pipelineInput = new PipelineTraceableInput(new PipelineTraceablePacket(
                IN_L3_UCAST_UNTAG_PACKET), UP_CP, getDataPlaneEntities(L3_UCAST_UNTAG));
        PipelineTraceable pipelineTraceable = setupTraceable();
        PipelineTraceableOutput pipelineOutput = pipelineTraceable.apply(pipelineInput);
        assertNotNull(pipelineOutput);

        assertThat(pipelineOutput.getHitChains().size(), is(1));
        assertThat(pipelineOutput.getResult(), is(PipelineTraceableOutput.PipelineTraceableResult.SUCCESS));

        PipelineTraceableHitChain hitChain = pipelineOutput.getHitChains().get(0);
        assertNotNull(hitChain);
        List<List<DataPlaneEntity>> chains = getHitChains(L3_UCAST_UNTAG);
        assertThat(chains.size(), is(1));

        // FIXME port is not null
        //assertNotNull(hitChain.getOutputPort());
        //assertThat(hitChain.getOutputPort().port(), is(PortNumber.CONTROLLER));
        assertNull(hitChain.getOutputPort());

        // FIXME hit chain is more than 5
        //assertThat(hitChain.getHitChain().size(), is(7));
        assertThat(hitChain.getHitChain().size(), is(5));

        // FIXME expect modification on the packets
        assertEquals(IN_L3_UCAST_UNTAG_PACKET, hitChain.getEgressPacket().getPacket());
        assertEquals(L3_UCAST_UNTAG_METADATA, hitChain.getEgressPacket().getMetadata());
        assertFalse(hitChain.isDropped());
        assertEquals(chains.get(0), hitChain.getHitChain());
    }

    /**
     * Test mpls ecmp routing for fabric-tna traceable.
     */
    @Test
    public void testMplsEcmp() {
        PipelineTraceableInput pipelineInput = new PipelineTraceableInput(new PipelineTraceablePacket(
                IN_MPLS_ECMP_PACKET), UP_CP, getDataPlaneEntities(MPLS_ECMP));
        PipelineTraceable pipelineTraceable = setupTraceable();
        PipelineTraceableOutput pipelineOutput = pipelineTraceable.apply(pipelineInput);
        assertNotNull(pipelineOutput);

        assertThat(pipelineOutput.getHitChains().size(), is(1));
        assertThat(pipelineOutput.getResult(), is(PipelineTraceableOutput.PipelineTraceableResult.SUCCESS));

        PipelineTraceableHitChain hitChain = pipelineOutput.getHitChains().get(0);
        assertNotNull(hitChain);
        List<List<DataPlaneEntity>> chains = getHitChains(MPLS_ECMP);
        assertThat(chains.size(), is(1));

        // FIXME port is not null
        //assertNotNull(hitChain.getOutputPort());
        //assertThat(hitChain.getOutputPort().port(), is(PortNumber.CONTROLLER));
        assertNull(hitChain.getOutputPort());

        // FIXME hit chain is more than 5
        //assertThat(hitChain.getHitChain().size(), is(7));
        assertThat(hitChain.getHitChain().size(), is(5));

        // FIXME expect modification on the packets
        assertEquals(IN_MPLS_ECMP_PACKET, hitChain.getEgressPacket().getPacket());
        assertEquals(MPLS_ECMP_METADATA, hitChain.getEgressPacket().getMetadata());
        assertFalse(hitChain.isDropped());
        assertEquals(chains.get(0), hitChain.getHitChain());
    }

    /**
     * Test l3 ecmp routing for fabric-tna traceable.
     */
    @Test
    public void testL3Ecmp() {
        PipelineTraceableInput pipelineInput = new PipelineTraceableInput(new PipelineTraceablePacket(
                IN_L3_ECMP_PACKET), DOWN_CP, getDataPlaneEntities(L3_ECMP));
        PipelineTraceable pipelineTraceable = setupTraceable();
        PipelineTraceableOutput pipelineOutput = pipelineTraceable.apply(pipelineInput);
        assertNotNull(pipelineOutput);

        assertThat(pipelineOutput.getHitChains().size(), is(1));
        assertThat(pipelineOutput.getResult(), is(PipelineTraceableOutput.PipelineTraceableResult.SUCCESS));

        // FIXME chains depend on the number of the members of the VLAN domain
        PipelineTraceableHitChain hitChain = pipelineOutput.getHitChains().get(0);
        assertNotNull(hitChain);
        List<List<DataPlaneEntity>> chains = getHitChains(L3_ECMP);
        assertThat(chains.size(), is(1));

        // FIXME port is not null
        //assertNotNull(hitChain.getOutputPort());
        //assertThat(hitChain.getOutputPort().port(), is(PortNumber.CONTROLLER));
        assertNull(hitChain.getOutputPort());

        // FIXME hit chain is more than 5
        //assertThat(hitChain.getHitChain().size(), is(7));
        assertThat(hitChain.getHitChain().size(), is(5));

        // FIXME expect modification on the packets
        assertEquals(IN_L3_ECMP_PACKET, hitChain.getEgressPacket().getPacket());
        assertEquals(L3_ECMP_METADATA, hitChain.getEgressPacket().getMetadata());
        assertFalse(hitChain.isDropped());
        assertEquals(chains.get(0), hitChain.getHitChain());
    }

}
