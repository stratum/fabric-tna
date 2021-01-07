// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package org.stratumproject.fabric.tna.behaviour.traceable;

import org.junit.Test;
import org.onlab.packet.MacAddress;
import org.onlab.util.ImmutableByteSequence;
import org.onosproject.net.pi.model.PiActionId;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiLpmFieldMatch;
import org.onosproject.net.pi.runtime.PiMatchKey;
import org.onosproject.net.pi.runtime.PiTableEntry;
import org.onosproject.net.pi.runtime.PiTernaryFieldMatch;
import org.stratumproject.fabric.tna.behaviour.P4InfoConstants;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.onlab.util.ImmutableByteSequence.copyFrom;
import static org.onosproject.net.pi.runtime.PiConstantsTest.DROP;

/**
 * Tests for TraceableUtils.
 */
public class TraceableUtilsTest extends PipelineTraceableTest {

    // LPM static fields
    private static final ImmutableByteSequence SUBNET = copyFrom(0x0a010100);
    private static final ImmutableByteSequence BIGGER_SUBNET = copyFrom(0x0a010000);
    private static final ImmutableByteSequence HOST = copyFrom(0x0a010102);
    private static final ImmutableByteSequence HOST_NOT_IN = copyFrom(0x0a010002);
    private static final int PREFIX_LENGTH = 24;
    private static final int HOST_PREFIX_LENGTH = 32;
    private static final int BIGGER_PREFIX_LENGTH = 16;
    private static final PiLpmFieldMatch LPM_SUBNET_MATCH = new PiLpmFieldMatch(P4InfoConstants.HDR_IPV4_DST,
            SUBNET, PREFIX_LENGTH);
    private static final PiLpmFieldMatch LPM_BIGGER_SUBNET_MATCH = new PiLpmFieldMatch(P4InfoConstants.HDR_IPV4_DST,
            BIGGER_SUBNET, BIGGER_PREFIX_LENGTH);
    private static final PiLpmFieldMatch LPM_HOST_MATCH = new PiLpmFieldMatch(P4InfoConstants.HDR_IPV4_DST,
            HOST, HOST_PREFIX_LENGTH);
    private static final PiLpmFieldMatch LPM_HOST_NOT_IN_MATCH = new PiLpmFieldMatch(P4InfoConstants.HDR_IPV4_DST,
            HOST_NOT_IN, HOST_PREFIX_LENGTH);

    // Ternary static fields
    private static final ImmutableByteSequence SUBNET_MASK = copyFrom(0xffffff00);
    private static final ImmutableByteSequence BIGGER_SUBNET_MASK = copyFrom(0xffff0000);
    private static final ImmutableByteSequence HOST_MASK = copyFrom(0xffffffff);
    private static final ImmutableByteSequence VLAN = copyFrom(0x8100);
    private static final ImmutableByteSequence VLAN_MASK = copyFrom(0xefff);
    private static final ImmutableByteSequence ETH_TYPE_VLAN = copyFrom(0x9100);
    private static final ImmutableByteSequence ETH_TYPE_VLAN_MASK = copyFrom(0xffff);
    private static final ImmutableByteSequence ETH_TYPE_IPV4 = copyFrom(0x0800);
    private static final ImmutableByteSequence ETH_TYPE_IPV4_MASK = copyFrom(0xffff);
    private static final ImmutableByteSequence MAC = copyFrom(MacAddress.valueOf("01:00:5e:00:00:00")
            .toBytes());
    private static final ImmutableByteSequence MAC_MASK = copyFrom(MacAddress.valueOf("ff:ff:ff:80:00:00")
            .toBytes());
    private static final ImmutableByteSequence MAC_IN = copyFrom(MacAddress.valueOf("01:00:5e:00:00:01")
            .toBytes());
    private static final ImmutableByteSequence MAC_NOT_IN = copyFrom(MacAddress.valueOf("01:00:5e:90:00:01")
            .toBytes());
    private static final ImmutableByteSequence EXACT_MASK = copyFrom(MacAddress.valueOf("ff:ff:ff:ff:ff:ff")
            .toBytes());
    private static final PiTernaryFieldMatch TER_SUBNET_MATCH = new PiTernaryFieldMatch(P4InfoConstants.HDR_IPV4_DST,
            SUBNET, SUBNET_MASK);
    private static final PiTernaryFieldMatch TER_BIGGER_SUBNET_MATCH = new PiTernaryFieldMatch(
            P4InfoConstants.HDR_IPV4_DST, BIGGER_SUBNET, BIGGER_SUBNET_MASK);
    private static final PiTernaryFieldMatch TER_HOST_MATCH = new PiTernaryFieldMatch(P4InfoConstants.HDR_IPV4_DST,
            HOST, HOST_MASK);
    private static final PiTernaryFieldMatch TER_HOST_NOT_IN_MATCH = new PiTernaryFieldMatch(
            P4InfoConstants.HDR_IPV4_DST, HOST_NOT_IN, HOST_MASK);
    private static final PiTernaryFieldMatch TER_VLAN_MATCH = new PiTernaryFieldMatch(P4InfoConstants.HDR_ETH_TYPE,
            VLAN, VLAN_MASK);
    private static final PiTernaryFieldMatch TER_ETH_TYPE_VLAN_MATCH = new PiTernaryFieldMatch(
            P4InfoConstants.HDR_ETH_TYPE, ETH_TYPE_VLAN, ETH_TYPE_VLAN_MASK);
    private static final PiTernaryFieldMatch TER_ETH_TYPE_IPV4_MATCH = new PiTernaryFieldMatch(
            P4InfoConstants.HDR_ETH_TYPE, ETH_TYPE_IPV4, ETH_TYPE_IPV4_MASK);
    private static final PiTernaryFieldMatch TER_MAC_MATCH = new PiTernaryFieldMatch(
            P4InfoConstants.HDR_ETH_DST, MAC, MAC_MASK);
    private static final PiTernaryFieldMatch TER_MAC_IN_MATCH = new PiTernaryFieldMatch(
            P4InfoConstants.HDR_ETH_DST, MAC_IN, EXACT_MASK);
    private static final PiTernaryFieldMatch TER_MAC_NOT_IN_MATCH = new PiTernaryFieldMatch(
            P4InfoConstants.HDR_ETH_DST, MAC_NOT_IN, EXACT_MASK);

    // Ternary entries static fields
    private static final PiTableEntry BEST_TER_ENTRY = PiTableEntry.builder()
            .forTable(P4InfoConstants.FABRIC_INGRESS_FORWARDING_BRIDGING)
            .withCookie(0xac)
            .withPriority(10)
            .withAction(PiAction.builder().withId(PiActionId.of(DROP)).build())
            .withTimeout(100)
            .build();
    private static final PiTableEntry CANDIDATE_TER_ENTRY_1 = PiTableEntry.builder()
            .forTable(P4InfoConstants.FABRIC_INGRESS_FORWARDING_BRIDGING)
            .withCookie(0xac)
            .withPriority(20)
            .withAction(PiAction.builder().withId(PiActionId.of(DROP)).build())
            .withTimeout(100)
            .build();
    private static final PiTableEntry CANDIDATE_TER_ENTRY_2 = PiTableEntry.builder()
            .forTable(P4InfoConstants.FABRIC_INGRESS_FORWARDING_BRIDGING)
            .withCookie(0xac)
            .withPriority(5)
            .withAction(PiAction.builder().withId(PiActionId.of(DROP)).build())
            .withTimeout(100)
            .build();

    // Lpm entries static fields
    private static final PiMatchKey BEST_MATCH_KEY = PiMatchKey.builder()
            .addFieldMatch(LPM_SUBNET_MATCH)
            .build();
    private static final PiTableEntry BEST_LPM_ENTRY = PiTableEntry.builder()
            .forTable(P4InfoConstants.FABRIC_INGRESS_FORWARDING_ROUTING_V4)
            .withCookie(0xac)
            .withMatchKey(BEST_MATCH_KEY)
            .withAction(PiAction.builder().withId(PiActionId.of(DROP)).build())
            .withTimeout(100)
            .build();
    private static final PiMatchKey CANDIDATE_MATCH_KEY_1 = PiMatchKey.builder()
            .addFieldMatch(LPM_HOST_MATCH)
            .build();
    private static final PiTableEntry CANDIDATE_LPM_ENTRY_1 = PiTableEntry.builder()
            .forTable(P4InfoConstants.FABRIC_INGRESS_FORWARDING_ROUTING_V4)
            .withCookie(0xac)
            .withMatchKey(CANDIDATE_MATCH_KEY_1)
            .withAction(PiAction.builder().withId(PiActionId.of(DROP)).build())
            .withTimeout(100)
            .build();
    private static final PiMatchKey CANDIDATE_MATCH_KEY_2 = PiMatchKey.builder()
            .addFieldMatch(LPM_BIGGER_SUBNET_MATCH)
            .build();
    private static final PiTableEntry CANDIDATE_LPM_ENTRY_2 = PiTableEntry.builder()
            .forTable(P4InfoConstants.FABRIC_INGRESS_FORWARDING_ROUTING_V4)
            .withCookie(0xac)
            .withMatchKey(CANDIDATE_MATCH_KEY_2)
            .withAction(PiAction.builder().withId(PiActionId.of(DROP)).build())
            .withTimeout(100)
            .build();
    private static final PiMatchKey DEFAULT_MATCH_KEY = PiMatchKey.builder()
            .build();
    private static final PiTableEntry DEFAULT_LPM_ENTRY = PiTableEntry.builder()
            .forTable(P4InfoConstants.FABRIC_INGRESS_FORWARDING_ROUTING_V4)
            .withCookie(0xac)
            .withMatchKey(DEFAULT_MATCH_KEY)
            .withAction(PiAction.builder().withId(PiActionId.of(DROP)).build())
            .withTimeout(100)
            .build();


    /**
     * Tests lpm match logic.
     */
    @Test
    public void testLpmMatch() {
        // 0x0a010100/24 vs the others
        assertTrue(TraceableUtils.lpmMatch(LPM_SUBNET_MATCH, LPM_SUBNET_MATCH));
        assertTrue(TraceableUtils.lpmMatch(LPM_SUBNET_MATCH, LPM_HOST_MATCH));
        assertFalse(TraceableUtils.lpmMatch(LPM_SUBNET_MATCH, LPM_HOST_NOT_IN_MATCH));
        assertFalse(TraceableUtils.lpmMatch(LPM_SUBNET_MATCH, LPM_BIGGER_SUBNET_MATCH));
        // 0x0a010102/32 vs the others
        assertTrue(TraceableUtils.lpmMatch(LPM_HOST_MATCH, LPM_HOST_MATCH));
        assertFalse(TraceableUtils.lpmMatch(LPM_HOST_MATCH, LPM_SUBNET_MATCH));
        assertFalse(TraceableUtils.lpmMatch(LPM_HOST_MATCH, LPM_HOST_NOT_IN_MATCH));
        assertFalse(TraceableUtils.lpmMatch(LPM_HOST_MATCH, LPM_BIGGER_SUBNET_MATCH));
        // 0x0a010002/32 vs the others
        assertTrue(TraceableUtils.lpmMatch(LPM_HOST_NOT_IN_MATCH, LPM_HOST_NOT_IN_MATCH));
        assertFalse(TraceableUtils.lpmMatch(LPM_HOST_NOT_IN_MATCH, LPM_SUBNET_MATCH));
        assertFalse(TraceableUtils.lpmMatch(LPM_HOST_NOT_IN_MATCH, LPM_HOST_MATCH));
        assertFalse(TraceableUtils.lpmMatch(LPM_HOST_NOT_IN_MATCH, LPM_BIGGER_SUBNET_MATCH));
        // 0x0a010000/16 vs the others
        assertTrue(TraceableUtils.lpmMatch(LPM_BIGGER_SUBNET_MATCH, LPM_BIGGER_SUBNET_MATCH));
        assertTrue(TraceableUtils.lpmMatch(LPM_BIGGER_SUBNET_MATCH, LPM_SUBNET_MATCH));
        assertTrue(TraceableUtils.lpmMatch(LPM_BIGGER_SUBNET_MATCH, LPM_HOST_MATCH));
        assertTrue(TraceableUtils.lpmMatch(LPM_BIGGER_SUBNET_MATCH, LPM_HOST_NOT_IN_MATCH));
    }

    /**
     * Tests ternary match logic with ipv4 dst.
     */
    @Test
    public void testTernaryMatchIpv4Dst() {
        // 0x0a010100/0xffffff00 vs others
        assertTrue(TraceableUtils.ternaryMatch(TER_SUBNET_MATCH, TER_SUBNET_MATCH));
        assertTrue(TraceableUtils.ternaryMatch(TER_SUBNET_MATCH, TER_HOST_MATCH));
        assertFalse(TraceableUtils.ternaryMatch(TER_SUBNET_MATCH, TER_HOST_NOT_IN_MATCH));
        assertFalse(TraceableUtils.ternaryMatch(TER_SUBNET_MATCH, TER_BIGGER_SUBNET_MATCH));
        assertFalse(TraceableUtils.ternaryMatch(TER_SUBNET_MATCH, TER_VLAN_MATCH));
        assertFalse(TraceableUtils.ternaryMatch(TER_SUBNET_MATCH, TER_ETH_TYPE_VLAN_MATCH));
        assertFalse(TraceableUtils.ternaryMatch(TER_SUBNET_MATCH, TER_ETH_TYPE_IPV4_MATCH));
        assertFalse(TraceableUtils.ternaryMatch(TER_SUBNET_MATCH, TER_MAC_MATCH));
        assertFalse(TraceableUtils.ternaryMatch(TER_SUBNET_MATCH, TER_MAC_IN_MATCH));
        assertFalse(TraceableUtils.ternaryMatch(TER_SUBNET_MATCH, TER_MAC_NOT_IN_MATCH));
        // 0x0a010102/0xffffffff vs the others
        assertTrue(TraceableUtils.ternaryMatch(TER_HOST_MATCH, TER_HOST_MATCH));
        assertFalse(TraceableUtils.ternaryMatch(TER_HOST_MATCH, TER_SUBNET_MATCH));
        assertFalse(TraceableUtils.ternaryMatch(TER_HOST_MATCH, TER_HOST_NOT_IN_MATCH));
        assertFalse(TraceableUtils.ternaryMatch(TER_HOST_MATCH, TER_BIGGER_SUBNET_MATCH));
        assertFalse(TraceableUtils.ternaryMatch(TER_HOST_MATCH, TER_VLAN_MATCH));
        assertFalse(TraceableUtils.ternaryMatch(TER_HOST_MATCH, TER_ETH_TYPE_VLAN_MATCH));
        assertFalse(TraceableUtils.ternaryMatch(TER_HOST_MATCH, TER_ETH_TYPE_IPV4_MATCH));
        assertFalse(TraceableUtils.ternaryMatch(TER_HOST_MATCH, TER_MAC_MATCH));
        assertFalse(TraceableUtils.ternaryMatch(TER_SUBNET_MATCH, TER_MAC_IN_MATCH));
        assertFalse(TraceableUtils.ternaryMatch(TER_SUBNET_MATCH, TER_MAC_NOT_IN_MATCH));
        // 0x0a010002/0xffffffff vs the others
        assertTrue(TraceableUtils.ternaryMatch(TER_HOST_NOT_IN_MATCH, TER_HOST_NOT_IN_MATCH));
        assertFalse(TraceableUtils.ternaryMatch(TER_HOST_NOT_IN_MATCH, TER_SUBNET_MATCH));
        assertFalse(TraceableUtils.ternaryMatch(TER_HOST_NOT_IN_MATCH, TER_HOST_MATCH));
        assertFalse(TraceableUtils.ternaryMatch(TER_HOST_NOT_IN_MATCH, TER_BIGGER_SUBNET_MATCH));
        assertFalse(TraceableUtils.ternaryMatch(TER_HOST_NOT_IN_MATCH, TER_VLAN_MATCH));
        assertFalse(TraceableUtils.ternaryMatch(TER_HOST_NOT_IN_MATCH, TER_ETH_TYPE_VLAN_MATCH));
        assertFalse(TraceableUtils.ternaryMatch(TER_HOST_NOT_IN_MATCH, TER_ETH_TYPE_IPV4_MATCH));
        assertFalse(TraceableUtils.ternaryMatch(TER_HOST_NOT_IN_MATCH, TER_MAC_MATCH));
        assertFalse(TraceableUtils.ternaryMatch(TER_HOST_NOT_IN_MATCH, TER_MAC_IN_MATCH));
        assertFalse(TraceableUtils.ternaryMatch(TER_HOST_NOT_IN_MATCH, TER_MAC_NOT_IN_MATCH));
        // 0x0a010000/0xffff0000 vs the others
        assertTrue(TraceableUtils.ternaryMatch(TER_BIGGER_SUBNET_MATCH, TER_BIGGER_SUBNET_MATCH));
        assertTrue(TraceableUtils.ternaryMatch(TER_BIGGER_SUBNET_MATCH, TER_SUBNET_MATCH));
        assertTrue(TraceableUtils.ternaryMatch(TER_BIGGER_SUBNET_MATCH, TER_HOST_MATCH));
        assertTrue(TraceableUtils.ternaryMatch(TER_BIGGER_SUBNET_MATCH, TER_HOST_NOT_IN_MATCH));
        assertFalse(TraceableUtils.ternaryMatch(TER_BIGGER_SUBNET_MATCH, TER_VLAN_MATCH));
        assertFalse(TraceableUtils.ternaryMatch(TER_BIGGER_SUBNET_MATCH, TER_ETH_TYPE_VLAN_MATCH));
        assertFalse(TraceableUtils.ternaryMatch(TER_BIGGER_SUBNET_MATCH, TER_ETH_TYPE_IPV4_MATCH));
        assertFalse(TraceableUtils.ternaryMatch(TER_BIGGER_SUBNET_MATCH, TER_MAC_MATCH));
        assertFalse(TraceableUtils.ternaryMatch(TER_BIGGER_SUBNET_MATCH, TER_MAC_IN_MATCH));
        assertFalse(TraceableUtils.ternaryMatch(TER_BIGGER_SUBNET_MATCH, TER_MAC_NOT_IN_MATCH));
    }

    /**
     * Tests ternary match logic with eth type.
     */
    @Test
    public void testTernaryMatchEthType() {
        // 0x8100/0xefff vs the others
        assertTrue(TraceableUtils.ternaryMatch(TER_VLAN_MATCH, TER_VLAN_MATCH));
        assertFalse(TraceableUtils.ternaryMatch(TER_VLAN_MATCH, TER_SUBNET_MATCH));
        assertFalse(TraceableUtils.ternaryMatch(TER_VLAN_MATCH, TER_HOST_MATCH));
        assertFalse(TraceableUtils.ternaryMatch(TER_VLAN_MATCH, TER_HOST_NOT_IN_MATCH));
        assertFalse(TraceableUtils.ternaryMatch(TER_VLAN_MATCH, TER_BIGGER_SUBNET_MATCH));
        assertTrue(TraceableUtils.ternaryMatch(TER_VLAN_MATCH, TER_ETH_TYPE_VLAN_MATCH));
        assertFalse(TraceableUtils.ternaryMatch(TER_VLAN_MATCH, TER_ETH_TYPE_IPV4_MATCH));
        assertFalse(TraceableUtils.ternaryMatch(TER_VLAN_MATCH, TER_MAC_MATCH));
        assertFalse(TraceableUtils.ternaryMatch(TER_VLAN_MATCH, TER_MAC_IN_MATCH));
        assertFalse(TraceableUtils.ternaryMatch(TER_VLAN_MATCH, TER_MAC_NOT_IN_MATCH));
        // 0x8100/0xffff vs the others
        assertTrue(TraceableUtils.ternaryMatch(TER_ETH_TYPE_VLAN_MATCH, TER_ETH_TYPE_VLAN_MATCH));
        assertFalse(TraceableUtils.ternaryMatch(TER_ETH_TYPE_VLAN_MATCH, TER_SUBNET_MATCH));
        assertFalse(TraceableUtils.ternaryMatch(TER_ETH_TYPE_VLAN_MATCH, TER_HOST_MATCH));
        assertFalse(TraceableUtils.ternaryMatch(TER_ETH_TYPE_VLAN_MATCH, TER_HOST_NOT_IN_MATCH));
        assertFalse(TraceableUtils.ternaryMatch(TER_ETH_TYPE_VLAN_MATCH, TER_BIGGER_SUBNET_MATCH));
        assertFalse(TraceableUtils.ternaryMatch(TER_ETH_TYPE_VLAN_MATCH, TER_VLAN_MATCH));
        assertFalse(TraceableUtils.ternaryMatch(TER_ETH_TYPE_VLAN_MATCH, TER_ETH_TYPE_IPV4_MATCH));
        assertFalse(TraceableUtils.ternaryMatch(TER_ETH_TYPE_VLAN_MATCH, TER_MAC_MATCH));
        assertFalse(TraceableUtils.ternaryMatch(TER_ETH_TYPE_VLAN_MATCH, TER_MAC_IN_MATCH));
        assertFalse(TraceableUtils.ternaryMatch(TER_ETH_TYPE_VLAN_MATCH, TER_MAC_NOT_IN_MATCH));
        // 0x0800/0xffff vs the others
        assertTrue(TraceableUtils.ternaryMatch(TER_ETH_TYPE_IPV4_MATCH, TER_ETH_TYPE_IPV4_MATCH));
        assertFalse(TraceableUtils.ternaryMatch(TER_ETH_TYPE_IPV4_MATCH, TER_SUBNET_MATCH));
        assertFalse(TraceableUtils.ternaryMatch(TER_ETH_TYPE_IPV4_MATCH, TER_HOST_MATCH));
        assertFalse(TraceableUtils.ternaryMatch(TER_ETH_TYPE_IPV4_MATCH, TER_HOST_NOT_IN_MATCH));
        assertFalse(TraceableUtils.ternaryMatch(TER_ETH_TYPE_IPV4_MATCH, TER_BIGGER_SUBNET_MATCH));
        assertFalse(TraceableUtils.ternaryMatch(TER_ETH_TYPE_IPV4_MATCH, TER_VLAN_MATCH));
        assertFalse(TraceableUtils.ternaryMatch(TER_ETH_TYPE_IPV4_MATCH, TER_ETH_TYPE_VLAN_MATCH));
        assertFalse(TraceableUtils.ternaryMatch(TER_ETH_TYPE_IPV4_MATCH, TER_MAC_MATCH));
        assertFalse(TraceableUtils.ternaryMatch(TER_ETH_TYPE_IPV4_MATCH, TER_MAC_IN_MATCH));
        assertFalse(TraceableUtils.ternaryMatch(TER_ETH_TYPE_IPV4_MATCH, TER_MAC_NOT_IN_MATCH));
    }

    /**
     * Tests ternary match logic with eth dst.
     */
    @Test
    public void testTernaryMatchEthDst() {
        // 0x01005e000000/0xffffff800000 vs the others
        assertTrue(TraceableUtils.ternaryMatch(TER_MAC_MATCH, TER_MAC_MATCH));
        assertTrue(TraceableUtils.ternaryMatch(TER_MAC_MATCH, TER_MAC_IN_MATCH));
        assertFalse(TraceableUtils.ternaryMatch(TER_MAC_MATCH, TER_MAC_NOT_IN_MATCH));
        // 0x01005e000001/0xffffffffffff vs the others
        assertTrue(TraceableUtils.ternaryMatch(TER_MAC_IN_MATCH, TER_MAC_IN_MATCH));
        assertFalse(TraceableUtils.ternaryMatch(TER_MAC_IN_MATCH, TER_MAC_MATCH));
        assertFalse(TraceableUtils.ternaryMatch(TER_MAC_IN_MATCH, TER_MAC_NOT_IN_MATCH));
        // 0x01005e900001/0xffffffffffff vs the others
        assertTrue(TraceableUtils.ternaryMatch(TER_MAC_NOT_IN_MATCH, TER_MAC_NOT_IN_MATCH));
        assertFalse(TraceableUtils.ternaryMatch(TER_MAC_NOT_IN_MATCH, TER_MAC_MATCH));
        assertFalse(TraceableUtils.ternaryMatch(TER_MAC_NOT_IN_MATCH, TER_MAC_IN_MATCH));
    }

    /**
     * Tests select best ternary entry.
     */
    @Test
    public void testSelectBestTernaryEntry() {
        // best priority is 10 vs 20 and 5
        assertEquals(CANDIDATE_TER_ENTRY_1, TraceableUtils.selectBestTerEntry(BEST_TER_ENTRY, CANDIDATE_TER_ENTRY_1));
        assertEquals(BEST_TER_ENTRY, TraceableUtils.selectBestTerEntry(BEST_TER_ENTRY, CANDIDATE_TER_ENTRY_2));
    }

    /**
     * Tests select best lpm entry.
     */
    @Test
    public void testSelectBestLpmEntry() {
        // best prefixLenght is 24 vs 32 and 16
        assertEquals(CANDIDATE_LPM_ENTRY_1, TraceableUtils.selectBestLpmEntry(BEST_LPM_ENTRY, CANDIDATE_LPM_ENTRY_1));
        assertEquals(BEST_LPM_ENTRY, TraceableUtils.selectBestLpmEntry(BEST_LPM_ENTRY, CANDIDATE_LPM_ENTRY_2));
    }

    /**
     * Tests select best lpm entry using default.
     */
    @Test
    public void testSelectBestLpmEntryWithDefault() {
        // best prefixLength 0 vs 16, 24 and 32
        assertEquals(CANDIDATE_LPM_ENTRY_1, TraceableUtils.selectBestLpmEntry(DEFAULT_LPM_ENTRY,
                CANDIDATE_LPM_ENTRY_1));
        assertEquals(CANDIDATE_LPM_ENTRY_1, TraceableUtils.selectBestLpmEntry(CANDIDATE_LPM_ENTRY_1,
                DEFAULT_LPM_ENTRY));
        assertEquals(CANDIDATE_LPM_ENTRY_2, TraceableUtils.selectBestLpmEntry(DEFAULT_LPM_ENTRY,
                CANDIDATE_LPM_ENTRY_2));
        assertEquals(CANDIDATE_LPM_ENTRY_2, TraceableUtils.selectBestLpmEntry(CANDIDATE_LPM_ENTRY_2,
                DEFAULT_LPM_ENTRY));
        assertEquals(BEST_LPM_ENTRY, TraceableUtils.selectBestLpmEntry(DEFAULT_LPM_ENTRY, BEST_LPM_ENTRY));
        assertEquals(BEST_LPM_ENTRY, TraceableUtils.selectBestLpmEntry(BEST_LPM_ENTRY, DEFAULT_LPM_ENTRY));
    }

}
