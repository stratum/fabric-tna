// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0
package org.stratumproject.fabric.tna.stats;

import junit.framework.TestCase;

import static org.junit.Assert.assertNotEquals;

public class StatisticDataValueTest extends TestCase {
    private static final long BYTE_1 = 50;
    private static final long BYTE_2 = 40;
    private static final long PACKET_1 = 2;
    private static final long PACKET_2 = 1;
    private static final long TIME_1 = 200;
    private static final long TIME_2 = 100;

    public void testStatisticDataValue() {
        StatisticDataValue value1 = StatisticDataValue.builder()
                .withByteCount(BYTE_1)
                .withPrevByteCount(BYTE_2)
                .withPacketCount(PACKET_1)
                .withPrevPacketCount(PACKET_2)
                .withTimeMs(TIME_1)
                .withPrevTimeMs(TIME_2)
                .build();
        StatisticDataValue value2 = StatisticDataValue.builder()
                .withByteCount(BYTE_2)
                .withPrevByteCount(BYTE_1)
                .withPacketCount(PACKET_2)
                .withPrevPacketCount(PACKET_1)
                .withTimeMs(TIME_2)
                .withPrevTimeMs(TIME_1)
                .build();
        StatisticDataValue value3 = StatisticDataValue.builder()
                .withByteCount(BYTE_1)
                .withPrevByteCount(BYTE_2)
                .withPacketCount(PACKET_1)
                .withPrevPacketCount(PACKET_2)
                .withTimeMs(TIME_1)
                .withPrevTimeMs(TIME_2)
                .build();

        assertEquals(value1.byteCount(), BYTE_1);
        assertEquals(value1.prevByteCount(), BYTE_2);
        assertEquals(value1.packetCount(), PACKET_1);
        assertEquals(value1.prevPacketCount(), PACKET_2);
        assertEquals(value1.timeMs(), TIME_1);
        assertEquals(value1.prevTimeMs(), TIME_2);
        assertEquals(value1.byteDiff(), BYTE_1 - BYTE_2);
        assertEquals(value1.packetDiff(), PACKET_1 - PACKET_2);
        assertEquals(value1.timeMsDiff(), TIME_1 - TIME_2);

        assertEquals(value1, value3);
        assertNotEquals(value1, value2);
        assertEquals(value1.hashCode(), value3.hashCode());
        assertNotEquals(value1.hashCode(), value2.hashCode());
        assertEquals(value1.toString(), value3.toString());
        assertNotEquals(value1.toString(), value2.toString());
        assertEquals(value1, value1);
        assertNotEquals(value1, null);
    }
}
