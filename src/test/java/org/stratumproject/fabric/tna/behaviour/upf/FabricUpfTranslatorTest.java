// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.behaviour.upf;

import org.junit.Test;
import org.onosproject.net.behaviour.upf.UpfInterface;
import org.onosproject.net.behaviour.upf.UpfProgrammableException;
import org.onosproject.net.behaviour.upf.UpfTerminationRule;
import org.onosproject.net.flow.FlowRule;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

public class FabricUpfTranslatorTest {

    private final FabricUpfTranslator upfTranslator = new FabricUpfTranslator();

    @Test
    public void fabricEntryToGtpTunnelPeerTest() {

    }

    @Test
    public void fabricEntryToUplinkUeSessionTest() {

    }

    @Test
    public void fabricEntryToDownlinkUeSessionTest() {

    }

    @Test
    public void fabricEntryToUplinkUpfTerminationTest() {
        UpfTerminationRule translatedUpfTerminationRule;
        UpfTerminationRule expected = TestUpfConstants.UPLINK_UPF_TERMINATION;
        try {
            translatedUpfTerminationRule = upfTranslator
                    .fabricEntryToUpfTerminationRule(TestUpfConstants.FABRIC_UPLINK_UPF_TERMINATION);
        } catch (UpfProgrammableException e) {
            assertThat("Fabric uplink interface should correctly translate to abstract interface without error",
                    false);
            return;
        }

        assertThat("Translated UPF Termination rule should be uplink.", translatedUpfTerminationRule.isUplink());
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
            assertThat("Fabric uplink interface should correctly translate to abstract interface without error",
                    false);
            return;
        }

        assertThat("Translated UPF Termination rule should be uplink.", translatedUpfTerminationRule.isUplink());
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
            assertThat("Fabric uplink interface should correctly translate to abstract interface without error",
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

    }

    @Test
    public void uplinkUeSessionToFabricEntryTest() {

    }

    @Test
    public void downlinkUeSessionToFabricEntryTest() {

    }

    @Test
    public void uplinkUpfTerminationToFabricEntryTest() {

    }

    @Test
    public void uplinkUpfQosTerminationToFabricEntryTest() {

    }

    @Test
    public void downlinkUpfTerminationToFabricEntryTest() {

    }

    @Test
    public void downlinkUpfQosTerminationToFabricEntryTest() {

    }
}
