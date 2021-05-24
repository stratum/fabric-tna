// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.stats;

import junit.framework.TestCase;
import org.onlab.packet.IpPrefix;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.TrafficSelector;

import static org.junit.Assert.assertNotEquals;

public class StatisticKeyTest extends TestCase {
    private static final int ID_1 = 1;
    private static final int ID_2 = 2;
    private static final TrafficSelector SEL_1 = DefaultTrafficSelector.builder()
            .matchIPSrc(IpPrefix.valueOf("192.168.1.0/24"))
            .build();
    private static final TrafficSelector SEL_2 = DefaultTrafficSelector.builder()
            .matchIPDst(IpPrefix.valueOf("192.168.1.0/24"))
            .build();

    public void testStatisticKey() {
        StatisticKey key1 = StatisticKey.builder()
                .withId(ID_1)
                .withSelector(SEL_1)
                .build();
        StatisticKey key2 = StatisticKey.builder()
                .withId(ID_2)
                .withSelector(SEL_2)
                .build();
        StatisticKey key3 = StatisticKey.builder()
                .withId(ID_1)
                .withSelector(SEL_1)
                .build();

        assertEquals(key1.id(), ID_1);
        assertEquals(key1.selector(), SEL_1);

        assertEquals(key1, key3);
        assertNotEquals(key1, key2);
        assertEquals(key1.hashCode(), key3.hashCode());
        assertNotEquals(key1.hashCode(), key2.hashCode());
        assertEquals(key1.toString(), key3.toString());
        assertNotEquals(key1.toString(), key2.toString());
        assertEquals(key1, key1);
        assertNotEquals(key1, null);
    }

}