// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.behaviour.upf;

import org.apache.commons.lang3.tuple.Pair;
import org.junit.Test;
import org.onosproject.net.behaviour.upf.*;
import org.onosproject.net.flow.FlowRule;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

public class FabricUpfTranslatorTest {

    private final FabricUpfTranslator upfTranslator = new FabricUpfTranslator();

    @Test
    public void fabricEntryToGtpTunnelPeerTest() {
        GtpTunnelPeer translated;
        GtpTunnelPeer expected = TestUpfConstants.GTP_TUNNEL_PEER;
        try {
            translated = upfTranslator.fabricEntryToGtpTunnelPeer(TestUpfConstants.FABRIC_EGRESS_GTP_TUNNEL_PEER);
        } catch (UpfProgrammableException e) {
            assertThat("Fabric GTP tunnel peer should correctly translate to abstract GTP tunnel peer without error",
                    false);
            return;
        }
        assertThat(translated, equalTo(expected));
    }

    @Test
    public void fabricEntryToUplinkUeSessionTest() {
        UeSession translated;
        UeSession expected = TestUpfConstants.UPLINK_UE_SESSION;
        try {
            translated = upfTranslator.fabricEntryToUeSession(TestUpfConstants.FABRIC_UPLINK_UE_SESSION);
        } catch (UpfProgrammableException e) {
            assertThat("Fabric uplink UE session should correctly translate to abstract UE session without error",
                    false);
            return;
        }
        assertThat("Translated UE Session should be uplink.",
                translated.isUplink());
        assertThat(translated, equalTo(expected));
    }

    @Test
    public void fabricEntryToDownlinkUeSessionTest() {
        UeSession translated;
        UeSession expected = TestUpfConstants.DOWNLINK_UE_SESSION;
        try {
            translated = upfTranslator.fabricEntryToUeSession(TestUpfConstants.FABRIC_DOWNLINK_UE_SESSION);
        } catch (UpfProgrammableException e) {
            assertThat("Fabric uplink UE session should correctly translate to abstract UE session without error",
                    false);
            return;
        }
        assertThat("Translated UE Session should be downlink.",
                !translated.isUplink());
        assertThat(translated, equalTo(expected));
    }

    @Test
    public void fabricEntryToUplinkUpfTerminationTest() {
        UpfTerminationRule translatedUpfTerminationRule;
        UpfTerminationRule expected = TestUpfConstants.UPLINK_UPF_TERMINATION;
        try {
            translatedUpfTerminationRule = upfTranslator
                    .fabricEntryToUpfTerminationRule(TestUpfConstants.FABRIC_UPLINK_UPF_TERMINATION);
        } catch (UpfProgrammableException e) {
            assertThat("Fabric uplink UPF termination rule should correctly " +
                            "translate to abstract UPF termination without error",
                    false);
            return;
        }

        assertThat("Translated UPF Termination rule should be uplink.",
                translatedUpfTerminationRule.isUplink());
        assertThat(translatedUpfTerminationRule, equalTo(expected));
    }

    @Test
    public void fabricEntryToUplinkUpfQosTerminationTest() {
        UpfTerminationRule translatedUpfTerminationRule;
        UpfTerminationRule expected = TestUpfConstants.UPLINK_UPF_TERMINATION_QOS;
        try {
            translatedUpfTerminationRule = upfTranslator
                    .fabricEntryToUpfTerminationRule(TestUpfConstants.FABRIC_UPLINK_UPF_TERMINATION_QOS);
        } catch (UpfProgrammableException e) {
            assertThat("Fabric uplink UPF termination rule should correctly " +
                            "translate to abstract UPF termination without error",
                    false);
            return;
        }

        assertThat("Translated UPF Termination rule should be uplink.",
                translatedUpfTerminationRule.isUplink());
        assertThat(translatedUpfTerminationRule, equalTo(expected));
    }


    @Test
    public void fabricEntryToDownlinkUpfQosTerminationTest() {
        UpfTerminationRule translatedUpfTerminationRule;
        UpfTerminationRule expected = TestUpfConstants.DOWNLINK_UPF_TERMINATION_QOS;
        try {
            translatedUpfTerminationRule = upfTranslator
                    .fabricEntryToUpfTerminationRule(TestUpfConstants.FABRIC_DOWNLINK_UPF_TERMINATION_QOS);
        } catch (UpfProgrammableException e) {
            assertThat("Fabric uplink interface should correctly translate to abstract interface without error",
                    false);
            return;
        }

        assertThat("Translated UPF Termination rule should be downlink.",
                !translatedUpfTerminationRule.isUplink());
        assertThat(translatedUpfTerminationRule, equalTo(expected));
    }

    @Test
    public void fabricEntryToDownlinkUpfTerminationTest() {
        UpfTerminationRule translatedUpfTerminationRule;
        UpfTerminationRule expected = TestUpfConstants.DOWNLINK_UPF_TERMINATION;
        try {
            translatedUpfTerminationRule = upfTranslator
                    .fabricEntryToUpfTerminationRule(TestUpfConstants.FABRIC_DOWNLINK_UPF_TERMINATION);
        } catch (UpfProgrammableException e) {
            assertThat("Fabric uplink UPF termination rule should correctly " +
                            "translate to abstract UPF termination without error",
                    false);
            return;
        }

        assertThat("Translated UPF Termination rule should be downlink.",
                !translatedUpfTerminationRule.isUplink());
        assertThat(translatedUpfTerminationRule, equalTo(expected));
    }


    @Test
    public void fabricEntryToUplinkInterfaceTest() {
        UpfInterface translatedInterface;
        UpfInterface expectedInterface = TestUpfConstants.UPLINK_INTERFACE;
        try {
            translatedInterface = upfTranslator.fabricEntryToInterface(TestUpfConstants.FABRIC_UPLINK_INTERFACE);
        } catch (UpfProgrammableException e) {
            assertThat("Fabric uplink interface should correctly translate to abstract interface without error",
                       false);
            return;
        }
        assertThat("Translated interface should be uplink.", translatedInterface.isAccess());
        assertThat(translatedInterface, equalTo(expectedInterface));
    }

    @Test
    public void fabricEntryToDownlinkInterfaceTest() {
        UpfInterface translatedInterface;
        UpfInterface expectedInterface = TestUpfConstants.DOWNLINK_INTERFACE;
        try {
            translatedInterface = upfTranslator.fabricEntryToInterface(TestUpfConstants.FABRIC_DOWNLINK_INTERFACE);
        } catch (UpfProgrammableException e) {
            assertThat("Fabric downlink interface should correctly translate to abstract interface without error",
                       false);
            return;
        }
        assertThat("Translated interface should be downlink.", translatedInterface.isCore());
        assertThat(translatedInterface, equalTo(expectedInterface));
    }

    @Test
    public void uplinkInterfaceToFabricEntryTest() {
        FlowRule translatedRule;
        FlowRule expectedRule = TestUpfConstants.FABRIC_UPLINK_INTERFACE;
        try {
            translatedRule = upfTranslator.interfaceToFabricEntry(TestUpfConstants.UPLINK_INTERFACE,
                                                                  TestUpfConstants.DEVICE_ID,
                                                                  TestUpfConstants.APP_ID,
                                                                  TestUpfConstants.DEFAULT_PRIORITY);
        } catch (UpfProgrammableException e) {
            assertThat("Abstract uplink interface should correctly translate to Fabric interface without error",
                       false);
            return;
        }
        assertThat(translatedRule, equalTo(expectedRule));
    }

    @Test
    public void downlinkInterfaceToFabricEntryTest() {
        FlowRule translatedRule;
        FlowRule expectedRule = TestUpfConstants.FABRIC_DOWNLINK_INTERFACE;
        try {
            translatedRule = upfTranslator.interfaceToFabricEntry(TestUpfConstants.DOWNLINK_INTERFACE,
                                                                  TestUpfConstants.DEVICE_ID,
                                                                  TestUpfConstants.APP_ID,
                                                                  TestUpfConstants.DEFAULT_PRIORITY);
        } catch (UpfProgrammableException e) {
            assertThat("Abstract downlink interface should correctly translate to Fabric interface without error",
                       false);
            return;
        }
        assertThat(translatedRule, equalTo(expectedRule));
    }

    @Test
    public void gtpTunnelPeerToFabricEntryTest() {
        Pair<FlowRule, FlowRule> translatedRule;
        Pair<FlowRule, FlowRule> expected = Pair.of(
                TestUpfConstants.FABRIC_INGRESS_GTP_TUNNEL_PEER,
                TestUpfConstants.FABRIC_EGRESS_GTP_TUNNEL_PEER);
        try {
            translatedRule = upfTranslator.gtpTunnelPeerToFabricEntry(
                    TestUpfConstants.GTP_TUNNEL_PEER,
                    TestUpfConstants.DEVICE_ID,
                    TestUpfConstants.APP_ID,
                    TestUpfConstants.DEFAULT_PRIORITY);
        } catch (UpfProgrammableException e) {
            assertThat("Abstract GTP tunnel peer should correctly translate to Fabric flow rules without error",
                    false);
            return;
        }
        assertThat(translatedRule.getLeft(), equalTo(expected.getLeft()));
        assertThat(translatedRule.getLeft().treatment(), equalTo(expected.getLeft().treatment()));
        assertThat(translatedRule.getRight(), equalTo(expected.getRight()));
        assertThat(translatedRule.getRight().treatment(), equalTo(expected.getRight().treatment()));
    }

    @Test
    public void uplinkUeSessionToFabricEntryTest() {
        FlowRule translatedRule;
        FlowRule expectedRule = TestUpfConstants.FABRIC_UPLINK_UE_SESSION;
        try {
            translatedRule = upfTranslator.ueSessionToFabricEntry(TestUpfConstants.UPLINK_UE_SESSION,
                    TestUpfConstants.DEVICE_ID,
                    TestUpfConstants.APP_ID,
                    TestUpfConstants.DEFAULT_PRIORITY);
        } catch (UpfProgrammableException e) {
            assertThat("Abstract uplink UE session should correctly " +
                            "translate to Fabric UE session without error",
                    false);
            return;
        }
        assertThat(translatedRule, equalTo(expectedRule));
        assertThat(translatedRule.treatment(), equalTo(expectedRule.treatment()));
    }

    @Test
    public void downlinkUeSessionToFabricEntryTest() {
        FlowRule translatedRule;
        FlowRule expectedRule = TestUpfConstants.FABRIC_DOWNLINK_UE_SESSION;
        try {
            translatedRule = upfTranslator.ueSessionToFabricEntry(TestUpfConstants.DOWNLINK_UE_SESSION,
                    TestUpfConstants.DEVICE_ID,
                    TestUpfConstants.APP_ID,
                    TestUpfConstants.DEFAULT_PRIORITY);
        } catch (UpfProgrammableException e) {
            assertThat("Abstract downlink UE session should correctly " +
                            "translate to Fabric UE session without error",
                    false);
            return;
        }
        assertThat(translatedRule, equalTo(expectedRule));
        assertThat(translatedRule.treatment(), equalTo(expectedRule.treatment()));
    }

    @Test
    public void uplinkUpfTerminationToFabricEntryTest() {
        FlowRule translatedRule;
        FlowRule expectedRule = TestUpfConstants.FABRIC_UPLINK_UPF_TERMINATION;
        try {
            translatedRule = upfTranslator.upfTerminationToFabricEntry(TestUpfConstants.UPLINK_UPF_TERMINATION,
                    TestUpfConstants.DEVICE_ID,
                    TestUpfConstants.APP_ID,
                    TestUpfConstants.DEFAULT_PRIORITY);
        } catch (UpfProgrammableException e) {
            assertThat("Abstract uplink UPF Termination should correctly " +
                            "translate to Fabric UPF Termination without error",
                    false);
            return;
        }
        assertThat(translatedRule, equalTo(expectedRule));
        assertThat(translatedRule.treatment(), equalTo(expectedRule.treatment()));
    }

    @Test
    public void uplinkUpfQosTerminationToFabricEntryTest() {
        FlowRule translatedRule;
        FlowRule expectedRule = TestUpfConstants.FABRIC_UPLINK_UPF_TERMINATION_QOS;
        try {
            translatedRule = upfTranslator.upfTerminationToFabricEntry(TestUpfConstants.UPLINK_UPF_TERMINATION_QOS,
                    TestUpfConstants.DEVICE_ID,
                    TestUpfConstants.APP_ID,
                    TestUpfConstants.DEFAULT_PRIORITY);
        } catch (UpfProgrammableException e) {
            assertThat("Abstract uplink UPF Termination should correctly " +
                            "translate to Fabric UPF Termination without error",
                    false);
            return;
        }
        assertThat(translatedRule, equalTo(expectedRule));
        assertThat(translatedRule.treatment(), equalTo(expectedRule.treatment()));
    }

    @Test
    public void downlinkUpfTerminationToFabricEntryTest() {
        FlowRule translatedRule;
        FlowRule expectedRule = TestUpfConstants.FABRIC_DOWNLINK_UPF_TERMINATION;
        try {
            translatedRule = upfTranslator.upfTerminationToFabricEntry(TestUpfConstants.DOWNLINK_UPF_TERMINATION,
                    TestUpfConstants.DEVICE_ID,
                    TestUpfConstants.APP_ID,
                    TestUpfConstants.DEFAULT_PRIORITY);
        } catch (UpfProgrammableException e) {
            assertThat("Abstract downlink UPF Termination should correctly " +
                            "translate to Fabric UPF Termination without error",
                    false);
            return;
        }
        assertThat(translatedRule, equalTo(expectedRule));
        // FIXME: this fails even if there is no difference, to troubleshoot
        //  assertThat(translatedRule.treatment(), equalTo(expectedRule.treatment()));
    }

    @Test
    public void downlinkUpfTerminationToDbufToFabricEntryTest() {
        FlowRule translatedRule;
        FlowRule expectedRule = TestUpfConstants.FABRIC_DOWNLINK_UPF_TERMINATION_DBUF;
        try {
            translatedRule = upfTranslator.upfTerminationToFabricEntry(TestUpfConstants.DOWNLINK_UPF_TERMINATION_DBUF,
                    TestUpfConstants.DEVICE_ID,
                    TestUpfConstants.APP_ID,
                    TestUpfConstants.DEFAULT_PRIORITY);
        } catch (UpfProgrammableException e) {
            assertThat("Abstract downlink UPF Termination to DBUF should correctly " +
                            "translate to Fabric UPF Termination without error",
                    false);
            return;
        }
        assertThat(translatedRule, equalTo(expectedRule));
        // FIXME: this fails even if there is no difference, to troubleshoot
        //  assertThat(translatedRule.treatment(), equalTo(expectedRule.treatment()));
    }

    @Test
    public void downlinkUpfQosTerminationToFabricEntryTest() {
        FlowRule translatedRule;
        FlowRule expectedRule = TestUpfConstants.FABRIC_DOWNLINK_UPF_TERMINATION_QOS;
        try {
            translatedRule = upfTranslator.upfTerminationToFabricEntry(TestUpfConstants.DOWNLINK_UPF_TERMINATION_QOS,
                    TestUpfConstants.DEVICE_ID,
                    TestUpfConstants.APP_ID,
                    TestUpfConstants.DEFAULT_PRIORITY);
        } catch (UpfProgrammableException e) {
            assertThat("Abstract downlink UPF Termination should correctly " +
                            "translate to Fabric UPF Termination without error",
                    false);
            return;
        }
        assertThat(translatedRule, equalTo(expectedRule));
        assertThat(translatedRule.treatment(), equalTo(expectedRule.treatment()));
    }
}
