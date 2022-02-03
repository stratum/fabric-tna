// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0
package org.stratumproject.fabric.tna.stats;

import junit.framework.TestCase;
import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;

import static org.junit.Assert.assertNotEquals;

public class StatisticDataKeyTest extends TestCase {
    private static final DeviceId DEVICE_ID_1 = DeviceId.deviceId("device1");
    private static final DeviceId DEVICE_ID_2 = DeviceId.deviceId("device2");
    private static final PortNumber PORT_1 = PortNumber.portNumber(1);
    private static final PortNumber PORT_2 = PortNumber.portNumber(2);

    public void testStaticDataKey() {
        StatisticDataKey key1 = StatisticDataKey.builder()
                .withDeviceId(DEVICE_ID_1)
                .withPortNumber(PORT_1)
                .withType(StatisticDataKey.Type.INGRESS)
                .build();
        StatisticDataKey key2 = StatisticDataKey.builder()
                .withDeviceId(DEVICE_ID_2)
                .withPortNumber(PORT_2)
                .withType(StatisticDataKey.Type.EGRESS)
                .build();
        StatisticDataKey key3 = StatisticDataKey.builder()
                .withDeviceId(DEVICE_ID_1)
                .withPortNumber(PORT_1)
                .withType(StatisticDataKey.Type.INGRESS)
                .build();

        assertEquals(key1.deviceId(), DEVICE_ID_1);
        assertEquals(key1.portNumber(), PORT_1);
        assertEquals(key1.type(), StatisticDataKey.Type.INGRESS);

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
