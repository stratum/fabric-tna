// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.behaviour.upf;

import org.junit.Test;
import org.onosproject.net.behaviour.upf.ForwardingActionRule;
import org.onosproject.net.behaviour.upf.PacketDetectionRule;
import org.onosproject.net.behaviour.upf.UpfInterface;
import org.onosproject.net.behaviour.upf.UpfProgrammableException;
import org.onosproject.net.flow.FlowRule;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

public class FabricUpfTranslatorTest {

    private final FabricUpfTranslator upfTranslator = new FabricUpfTranslator(TestDistributedFabricUpfStore.build());

    @Test
    public void fabricEntryToUplinkPdrTest() {
        PacketDetectionRule expectedPdr = TestUpfConstants.UPLINK_PDR;
        PacketDetectionRule translatedPdr;
        try {
            translatedPdr = upfTranslator.fabricEntryToPdr(TestUpfConstants.FABRIC_UPLINK_PDR);
        } catch (UpfProgrammableException e) {
            assertThat("Fabric uplink PDR should translate to abstract PDR without error.", false);
            return;
        }
        assertThat("Translated PDR should be uplink.", translatedPdr.matchesEncapped());
        assertThat(translatedPdr, equalTo(expectedPdr));
    }

    @Test
    public void fabricEntryToUplinkPriorityPdrTest() {
        PacketDetectionRule expectedPdr = TestUpfConstants.UPLINK_PRIORITY_PDR;
        PacketDetectionRule translatedPdr;
        try {
            translatedPdr = upfTranslator.fabricEntryToPdr(TestUpfConstants.FABRIC_UPLINK_PRIORITY_PDR);
        } catch (UpfProgrammableException e) {
            assertThat("Fabric uplink PDR should translate to abstract PDR without error.", false);
            return;
        }
        assertThat("Translated PDR should be uplink.", translatedPdr.matchesEncapped());
        assertThat(translatedPdr, equalTo(expectedPdr));
    }

    @Test
    public void fabricEntryToDownlinkPdrTest() {
        PacketDetectionRule expectedPdr = TestUpfConstants.DOWNLINK_PDR;
        PacketDetectionRule translatedPdr;
        try {
            translatedPdr = upfTranslator.fabricEntryToPdr(TestUpfConstants.FABRIC_DOWNLINK_PDR);
        } catch (UpfProgrammableException e) {
            assertThat("Fabric downlink PDR should translate to abstract PDR without error.", false);
            return;
        }

        assertThat("Translated PDR should be downlink.", translatedPdr.matchesUnencapped());
        assertThat(translatedPdr, equalTo(expectedPdr));
    }

    @Test
    public void fabricEntryToDownlinkPriorityPdrTest() {
        PacketDetectionRule expectedPdr = TestUpfConstants.DOWNLINK_PRIORITY_PDR;
        PacketDetectionRule translatedPdr;
        try {
            translatedPdr = upfTranslator.fabricEntryToPdr(TestUpfConstants.FABRIC_DOWNLINK_PRIORITY_PDR);
        } catch (UpfProgrammableException e) {
            assertThat("Fabric downlink PDR should translate to abstract PDR without error.", false);
            return;
        }

        assertThat("Translated PDR should be downlink.", translatedPdr.matchesUnencapped());
        assertThat(translatedPdr, equalTo(expectedPdr));
    }

    @Test
    public void fabricEntryToUplinkFarTest() {
        ForwardingActionRule translatedFar;
        ForwardingActionRule expectedFar = TestUpfConstants.UPLINK_FAR;
        try {
            translatedFar = upfTranslator.fabricEntryToFar(TestUpfConstants.FABRIC_UPLINK_FAR);
        } catch (UpfProgrammableException e) {
            assertThat("Fabric uplink FAR should correctly translate to abstract FAR without error",
                       false);
            return;
        }
        assertThat("Translated FAR should be uplink.", translatedFar.forwards());
        assertThat(translatedFar, equalTo(expectedFar));
    }

    @Test
    public void fabricEntryToDownlinkFarTest() {
        ForwardingActionRule translatedFar;
        ForwardingActionRule expectedFar = TestUpfConstants.DOWNLINK_FAR;
        try {
            translatedFar = upfTranslator.fabricEntryToFar(TestUpfConstants.FABRIC_DOWNLINK_FAR);
        } catch (UpfProgrammableException e) {
            assertThat("Fabric downlink FAR should correctly translate to abstract FAR without error",
                       false);
            return;
        }
        assertThat("Translated FAR should be downlink.", translatedFar.encaps());
        assertThat(translatedFar, equalTo(expectedFar));
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
    public void downlinkPdrToFabricEntryTest() {
        FlowRule translatedRule;
        FlowRule expectedRule = TestUpfConstants.FABRIC_DOWNLINK_PDR;
        try {
            translatedRule = upfTranslator.pdrToFabricEntry(TestUpfConstants.DOWNLINK_PDR,
                                                            TestUpfConstants.DEVICE_ID,
                                                            TestUpfConstants.APP_ID,
                                                            TestUpfConstants.DEFAULT_PRIORITY);
        } catch (UpfProgrammableException e) {
            assertThat("Abstract downlink PDR should correctly translate to Fabric PDR without error",
                       false);
            return;
        }
        assertThat(translatedRule, equalTo(expectedRule));
    }

    @Test
    public void downlinkPdrToFabricPriorityEntryTest() {
        FlowRule translatedRule;
        FlowRule expectedRule = TestUpfConstants.FABRIC_DOWNLINK_PRIORITY_PDR;
        try {
            translatedRule = upfTranslator.pdrToFabricEntry(TestUpfConstants.DOWNLINK_PRIORITY_PDR,
                                                            TestUpfConstants.DEVICE_ID,
                                                            TestUpfConstants.APP_ID,
                                                            TestUpfConstants.DEFAULT_PRIORITY);
        } catch (UpfProgrammableException e) {
            assertThat("Abstract downlink PDR should correctly translate to Fabric PDR without error",
                       false);
            return;
        }
        assertThat(translatedRule, equalTo(expectedRule));
    }

    @Test
    public void uplinkFarToFabricEntryTest() {
        FlowRule translatedRule;
        FlowRule expectedRule = TestUpfConstants.FABRIC_UPLINK_FAR;
        try {
            translatedRule = upfTranslator.farToFabricEntry(TestUpfConstants.UPLINK_FAR,
                                                            TestUpfConstants.DEVICE_ID,
                                                            TestUpfConstants.APP_ID,
                                                            TestUpfConstants.DEFAULT_PRIORITY);
        } catch (UpfProgrammableException e) {
            assertThat("Abstract uplink FAR should correctly translate to Fabric FAR without error",
                       false);
            return;
        }
        assertThat(translatedRule, equalTo(expectedRule));
    }

    @Test
    public void uplinkPdrToFabricEntryTest() {
        FlowRule translatedRule;
        FlowRule expectedRule = TestUpfConstants.FABRIC_UPLINK_PDR;
        try {
            translatedRule = upfTranslator.pdrToFabricEntry(TestUpfConstants.UPLINK_PDR,
                                                            TestUpfConstants.DEVICE_ID,
                                                            TestUpfConstants.APP_ID,
                                                            TestUpfConstants.DEFAULT_PRIORITY);
        } catch (UpfProgrammableException e) {
            assertThat("Abstract uplink PDR should correctly translate to Fabric PDR without error",
                       false);
            return;
        }
        assertThat(translatedRule, equalTo(expectedRule));
    }

    @Test
    public void uplinkPriorityPdrToFabricEntryTest() {
        FlowRule translatedRule;
        FlowRule expectedRule = TestUpfConstants.FABRIC_UPLINK_PRIORITY_PDR;
        try {
            translatedRule = upfTranslator.pdrToFabricEntry(TestUpfConstants.UPLINK_PRIORITY_PDR,
                                                            TestUpfConstants.DEVICE_ID,
                                                            TestUpfConstants.APP_ID,
                                                            TestUpfConstants.DEFAULT_PRIORITY);
        } catch (UpfProgrammableException e) {
            assertThat("Abstract uplink PDR should correctly translate to Fabric PDR without error",
                       false);
            return;
        }
        assertThat(translatedRule, equalTo(expectedRule));
    }

    @Test
    public void downlinkFarToFabricEntryTest() {
        FlowRule translatedRule;
        FlowRule expectedRule = TestUpfConstants.FABRIC_DOWNLINK_FAR;
        try {
            translatedRule = upfTranslator.farToFabricEntry(TestUpfConstants.DOWNLINK_FAR,
                                                            TestUpfConstants.DEVICE_ID,
                                                            TestUpfConstants.APP_ID,
                                                            TestUpfConstants.DEFAULT_PRIORITY);
        } catch (UpfProgrammableException e) {
            assertThat("Abstract downlink FAR should correctly translate to Fabric FAR without error",
                       false);
            return;
        }
        assertThat(translatedRule, equalTo(expectedRule));
    }
}
