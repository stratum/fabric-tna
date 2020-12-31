// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package org.stratumproject.fabric.tna.behaviour.traceable;

import org.junit.Before;
import org.junit.Test;
import org.onosproject.net.DataPlaneEntity;
import org.onosproject.net.PipelineTraceableHitChain;
import org.onosproject.net.PipelineTraceableInput;
import org.onosproject.net.PipelineTraceableOutput;
import org.onosproject.net.PipelineTraceablePacket;
import org.onosproject.net.PortNumber;
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
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertThat;
import static org.stratumproject.fabric.tna.behaviour.traceable.PipelineTraceableTest.TraceableTest.*;
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

        // Verify the ingress pipeline
        List<PipelineTraceableCtrl> egressPipeline = ((AbstractFabricPipelineTraceable) pipelineTraceable)
            .egressPipeline;
        assertThat(egressPipeline.size(), is(1));
        assertTrue(egressPipeline.get(0) instanceof PipelineTraceableEgress);
    }

    /**
     * Test punt ip untag for fabric-tna traceable.
     */
    @Test
    public void testPuntIPUntag() {
        PipelineTraceableInput pipelineInput = new PipelineTraceableInput(getPipelineTraceablePacket(
                IN_PUNT_IP_PACKET), DOWN_CP, getDataPlaneEntities(PUNT_IP_UNTAG));
        PipelineTraceable pipelineTraceable = setupTraceable();
        PipelineTraceableOutput pipelineOutput = pipelineTraceable.apply(pipelineInput);
        assertNotNull(pipelineOutput);

        assertThat(pipelineOutput.hitChains().size(), is(1));
        assertThat(pipelineOutput.result(), is(PipelineTraceableOutput.PipelineTraceableResult.SUCCESS));

        PipelineTraceableHitChain hitChain = pipelineOutput.hitChains().get(0);
        assertNotNull(hitChain);
        List<List<DataPlaneEntity>> chains = getHitChains(PUNT_IP_UNTAG);
        assertThat(chains.size(), is(1));

        assertNotNull(hitChain.outputPort());
        assertThat(hitChain.outputPort().port(), is(PortNumber.CONTROLLER));

        assertThat(hitChain.hitChain().size(), is(4));

        assertEquals(IN_PUNT_IP_PACKET, hitChain.egressPacket().packet());
        assertEquals(PUNT_IP_METADATA, hitChain.egressPacket().metadata());
        assertFalse(hitChain.isDropped());
        assertEquals(chains.get(0), hitChain.hitChain());
    }

    /**
     * Test punt ip tagged for fabric-tna traceable.
     */
    @Test
    public void testPuntIPTag() {
        PipelineTraceableInput pipelineInput = new PipelineTraceableInput(getPipelineTraceablePacket(
                IN_PUNT_IP_PACKET_TAG), DOWN_CP_TAG, getDataPlaneEntities(PUNT_IP_TAG));
        PipelineTraceable pipelineTraceable = setupTraceable();
        PipelineTraceableOutput pipelineOutput = pipelineTraceable.apply(pipelineInput);
        assertNotNull(pipelineOutput);

        assertThat(pipelineOutput.hitChains().size(), is(1));
        assertThat(pipelineOutput.result(), is(PipelineTraceableOutput.PipelineTraceableResult.SUCCESS));

        PipelineTraceableHitChain hitChain = pipelineOutput.hitChains().get(0);
        assertNotNull(hitChain);
        List<List<DataPlaneEntity>> chains = getHitChains(PUNT_IP_TAG);
        assertThat(chains.size(), is(1));

        assertNotNull(hitChain.outputPort());
        assertThat(hitChain.outputPort().port(), is(PortNumber.CONTROLLER));

        assertThat(hitChain.hitChain().size(), is(4));

        assertEquals(IN_PUNT_IP_PACKET_TAG, hitChain.egressPacket().packet());
        assertEquals(PUNT_IP_METADATA_TAG, hitChain.egressPacket().metadata());
        assertFalse(hitChain.isDropped());
        assertEquals(chains.get(0), hitChain.hitChain());
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

        assertThat(pipelineOutput.hitChains().size(), is(4));
        assertThat(pipelineOutput.result(), is(PipelineTraceableOutput.PipelineTraceableResult.SUCCESS));
        List<List<DataPlaneEntity>> chains = getHitChains(ARP_UNTAG);
        assertThat(chains.size(), is(4));

        // Controller
        PipelineTraceableHitChain hitChain = pipelineOutput.hitChains().get(0);
        assertNotNull(hitChain);
        assertNotNull(hitChain.outputPort());
        assertThat(hitChain.outputPort().port(), is(PortNumber.CONTROLLER));
        assertThat(hitChain.hitChain().size(), is(5));
        assertEquals(IN_ARP_PACKET, hitChain.egressPacket().packet());
        assertEquals(ARP_METADATA, hitChain.egressPacket().metadata());
        assertFalse(hitChain.isDropped());
        assertEquals(chains.get(0), hitChain.hitChain());

        // Input port
        hitChain = pipelineOutput.hitChains().get(1);
        assertNotNull(hitChain);
        assertNotNull(hitChain.outputPort());
        assertThat(hitChain.outputPort().port(), is(DOWN_PORT));
        assertThat(hitChain.hitChain().size(), is(6));
        assertEquals(IN_ARP_PACKET, hitChain.egressPacket().packet());
        assertEquals(ARP_METADATA, hitChain.egressPacket().metadata());
        assertTrue(hitChain.isDropped());
        assertEquals(chains.get(1), hitChain.hitChain());

        // Other members
        hitChain = pipelineOutput.hitChains().get(2);
        assertNotNull(hitChain.outputPort());
        assertThat(hitChain.outputPort().port(), is(MEMBER_2));
        assertThat(hitChain.hitChain().size(), is(7));
        assertEquals(IN_ARP_PACKET, hitChain.egressPacket().packet());
        assertEquals(ARP_METADATA_2, hitChain.egressPacket().metadata());
        assertFalse(hitChain.isDropped());
        assertEquals(chains.get(2), hitChain.hitChain());

        hitChain = pipelineOutput.hitChains().get(3);
        assertNotNull(hitChain.outputPort());
        assertThat(hitChain.outputPort().port(), is(MEMBER_1));
        assertThat(hitChain.hitChain().size(), is(7));
        assertEquals(IN_ARP_PACKET, hitChain.egressPacket().packet());
        assertEquals(ARP_METADATA_1, hitChain.egressPacket().metadata());
        assertFalse(hitChain.isDropped());
        assertEquals(chains.get(3), hitChain.hitChain());
    }

    /**
     * Test punt lldp for fabric-tna traceable.
     */
    @Test
    public void testPuntLldp() {
        PipelineTraceableInput pipelineInput = new PipelineTraceableInput(new PipelineTraceablePacket(
                IN_PUNT_LLDP_PACKET), UP_CP_1, getDataPlaneEntities(PUNT_LLDP));
        PipelineTraceable pipelineTraceable = setupTraceable();
        PipelineTraceableOutput pipelineOutput = pipelineTraceable.apply(pipelineInput);
        assertNotNull(pipelineOutput);

        assertThat(pipelineOutput.hitChains().size(), is(1));
        assertThat(pipelineOutput.result(), is(PipelineTraceableOutput.PipelineTraceableResult.SUCCESS));

        PipelineTraceableHitChain hitChain = pipelineOutput.hitChains().get(0);
        assertNotNull(hitChain);
        List<List<DataPlaneEntity>> chains = getHitChains(PUNT_LLDP);
        assertThat(chains.size(), is(1));

        assertNotNull(hitChain.outputPort());
        assertThat(hitChain.outputPort().port(), is(PortNumber.CONTROLLER));
        assertThat(hitChain.hitChain().size(), is(2));
        assertEquals(IN_PUNT_LLDP_PACKET, hitChain.egressPacket().packet());
        assertEquals(PUNT_LLDP_METADATA, hitChain.egressPacket().metadata());
        assertFalse(hitChain.isDropped());
        assertEquals(chains.get(0), hitChain.hitChain());
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

        assertThat(pipelineOutput.hitChains().size(), is(1));
        assertThat(pipelineOutput.result(), is(PipelineTraceableOutput.PipelineTraceableResult.SUCCESS));

        PipelineTraceableHitChain hitChain = pipelineOutput.hitChains().get(0);
        assertNotNull(hitChain);
        List<List<DataPlaneEntity>> chains = getHitChains(L2_BRIDG_UNTAG);
        assertThat(chains.size(), is(1));

        assertNotNull(hitChain.outputPort());
        assertThat(hitChain.outputPort().port(), is(MEMBER_1));
        assertThat(hitChain.hitChain().size(), is(6));
        assertEquals(IN_L2_BRIDG_UNTAG_PACKET, hitChain.egressPacket().packet());
        assertEquals(L2_BRIDG_UNTAG_METADATA, hitChain.egressPacket().metadata());
        assertFalse(hitChain.isDropped());
        assertEquals(chains.get(0), hitChain.hitChain());
    }

    /**
     * Test l2 bridging miss for fabric-tna traceable.
     */
    @Test
    public void testL2BridingMiss() {
        PipelineTraceableInput pipelineInput = new PipelineTraceableInput(new PipelineTraceablePacket(
                IN_L2_BRIDG_MISS_PACKET), DOWN_CP_TAG, getDataPlaneEntities(L2_BRIDG_MISS));
        PipelineTraceable pipelineTraceable = setupTraceable();
        PipelineTraceableOutput pipelineOutput = pipelineTraceable.apply(pipelineInput);
        assertNotNull(pipelineOutput);

        assertThat(pipelineOutput.hitChains().size(), is(1));
        assertThat(pipelineOutput.result(), is(PipelineTraceableOutput.PipelineTraceableResult.DROPPED));

        PipelineTraceableHitChain hitChain = pipelineOutput.hitChains().get(0);
        assertNotNull(hitChain);
        List<List<DataPlaneEntity>> chains = getHitChains(L2_BRIDG_MISS);
        assertThat(chains.size(), is(1));

        assertNotNull(hitChain.outputPort());
        assertThat(hitChain.outputPort().port(), is(DOWN_PORT_TAG));
        assertThat(hitChain.hitChain().size(), is(5));
        assertEquals(IN_L2_BRIDG_MISS_PACKET, hitChain.egressPacket().packet());
        assertEquals(L2_BRIDG_MISS_METADATA, hitChain.egressPacket().metadata());
        assertTrue(hitChain.isDropped());
        assertEquals(chains.get(0), hitChain.hitChain());
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

        assertThat(pipelineOutput.hitChains().size(), is(3));
        assertThat(pipelineOutput.result(), is(PipelineTraceableOutput.PipelineTraceableResult.SUCCESS));
        List<List<DataPlaneEntity>> chains = getHitChains(L2_BROAD_UNTAG);
        assertThat(chains.size(), is(3));

        // Input port
        PipelineTraceableHitChain hitChain = pipelineOutput.hitChains().get(0);
        assertNotNull(hitChain);
        assertNotNull(hitChain.outputPort());
        assertThat(hitChain.outputPort().port(), is(DOWN_PORT));
        assertThat(hitChain.hitChain().size(), is(5));
        assertEquals(IN_L2_BROAD_UNTAG_PACKET, hitChain.egressPacket().packet());
        assertEquals(L2_BROAD_UNTAG_METADATA, hitChain.egressPacket().metadata());
        assertTrue(hitChain.isDropped());
        assertEquals(chains.get(0), hitChain.hitChain());

        // Other members
        hitChain = pipelineOutput.hitChains().get(1);
        assertNotNull(hitChain);
        assertNotNull(hitChain.outputPort());
        assertThat(hitChain.outputPort().port(), is(MEMBER_2));
        assertThat(hitChain.hitChain().size(), is(6));
        assertEquals(IN_L2_BROAD_UNTAG_PACKET, hitChain.egressPacket().packet());
        assertEquals(L2_BROAD_UNTAG_METADATA_2, hitChain.egressPacket().metadata());
        assertFalse(hitChain.isDropped());
        assertEquals(chains.get(1), hitChain.hitChain());

        hitChain = pipelineOutput.hitChains().get(2);
        assertNotNull(hitChain);
        assertNotNull(hitChain.outputPort());
        assertThat(hitChain.outputPort().port(), is(MEMBER_1));
        assertThat(hitChain.hitChain().size(), is(6));
        assertEquals(IN_L2_BROAD_UNTAG_PACKET, hitChain.egressPacket().packet());
        assertEquals(L2_BROAD_UNTAG_METADATA_1, hitChain.egressPacket().metadata());
        assertFalse(hitChain.isDropped());
        assertEquals(chains.get(2), hitChain.hitChain());
    }

    /**
     * Test l3 unicast routing for fabric-tna traceable.
     */
    @Test
    public void testL3Unicast() {
        PipelineTraceableInput pipelineInput = new PipelineTraceableInput(new PipelineTraceablePacket(
                IN_L3_UCAST_UNTAG_PACKET), UP_CP_1, getDataPlaneEntities(L3_UCAST_UNTAG));
        PipelineTraceable pipelineTraceable = setupTraceable();
        PipelineTraceableOutput pipelineOutput = pipelineTraceable.apply(pipelineInput);
        assertNotNull(pipelineOutput);

        assertThat(pipelineOutput.hitChains().size(), is(1));
        assertThat(pipelineOutput.result(), is(PipelineTraceableOutput.PipelineTraceableResult.SUCCESS));

        PipelineTraceableHitChain hitChain = pipelineOutput.hitChains().get(0);
        assertNotNull(hitChain);
        List<List<DataPlaneEntity>> chains = getHitChains(L3_UCAST_UNTAG);
        assertThat(chains.size(), is(1));

        assertNotNull(hitChain.outputPort());
        assertThat(hitChain.outputPort().port(), is(DOWN_PORT));
        assertThat(hitChain.hitChain().size(), is(7));
        assertEquals(OUT_L3_UCAST_UNTAG_PACKET, hitChain.egressPacket().packet());
        assertEquals(L3_UCAST_UNTAG_METADATA, hitChain.egressPacket().metadata());
        assertFalse(hitChain.isDropped());
        assertEquals(chains.get(0), hitChain.hitChain());
    }

    /**
     * Test mpls ecmp routing for fabric-tna traceable.
     */
    @Test
    public void testMplsEcmp() {
        PipelineTraceableInput pipelineInput = new PipelineTraceableInput(new PipelineTraceablePacket(
                IN_MPLS_ECMP_PACKET), UP_CP_1, getDataPlaneEntities(MPLS_ECMP));
        PipelineTraceable pipelineTraceable = setupTraceable();
        PipelineTraceableOutput pipelineOutput = pipelineTraceable.apply(pipelineInput);
        assertNotNull(pipelineOutput);

        assertThat(pipelineOutput.hitChains().size(), is(1));
        assertThat(pipelineOutput.result(), is(PipelineTraceableOutput.PipelineTraceableResult.SUCCESS));

        PipelineTraceableHitChain hitChain = pipelineOutput.hitChains().get(0);
        assertNotNull(hitChain);
        List<List<DataPlaneEntity>> chains = getHitChains(MPLS_ECMP);
        assertThat(chains.size(), is(1));

        assertNotNull(hitChain.outputPort());
        assertThat(hitChain.outputPort().port(), is(UP_PORT_2));
        assertThat(hitChain.hitChain().size(), is(7));
        assertEquals(OUT_MPLS_ECMP_PACKET, hitChain.egressPacket().packet());
        assertEquals(MPLS_ECMP_METADATA, hitChain.egressPacket().metadata());
        assertFalse(hitChain.isDropped());
        assertEquals(chains.get(0), hitChain.hitChain());
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

        assertThat(pipelineOutput.hitChains().size(), is(2));
        assertThat(pipelineOutput.result(), is(PipelineTraceableOutput.PipelineTraceableResult.SUCCESS));
        List<List<DataPlaneEntity>> chains = getHitChains(L3_ECMP);
        assertThat(chains.size(), is(2));

        PipelineTraceableHitChain hitChain = pipelineOutput.hitChains().get(0);
        assertNotNull(hitChain);
        assertNotNull(hitChain.outputPort());
        assertThat(hitChain.outputPort().port(), is(UP_PORT_1));
        assertThat(hitChain.hitChain().size(), is(7));
        assertEquals(OUT_L3_ECMP_PACKET_1, hitChain.egressPacket().packet());
        assertEquals(L3_ECMP_METADATA_1, hitChain.egressPacket().metadata());
        assertFalse(hitChain.isDropped());
        assertEquals(chains.get(0), hitChain.hitChain());

        // Other ECMP path
        hitChain = pipelineOutput.hitChains().get(1);
        assertNotNull(hitChain);
        assertNotNull(hitChain.outputPort());
        assertThat(hitChain.outputPort().port(), is(UP_PORT_2));
        assertThat(hitChain.hitChain().size(), is(7));
        assertEquals(OUT_L3_ECMP_PACKET_2, hitChain.egressPacket().packet());
        assertEquals(L3_ECMP_METADATA_2, hitChain.egressPacket().metadata());
        assertFalse(hitChain.isDropped());
        assertEquals(chains.get(1), hitChain.hitChain());
    }

}
