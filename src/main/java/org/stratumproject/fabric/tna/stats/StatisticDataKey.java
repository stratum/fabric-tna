// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0
package org.stratumproject.fabric.tna.stats;

import com.google.common.base.MoreObjects;
import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;

import java.util.Objects;

/**
 * Data structure to identify a statistics result.
 */
public final class StatisticDataKey {
    /**
     * Device ID this statistic data is associated with.
     */
    private DeviceId deviceId;

    /**
     * Port number this statistic data is associated with.
     */
    private PortNumber portNumber;

    /**
     * Type of the statistic data.
     */
    private Type type;

    public enum Type {
        INGRESS,
        EGRESS
    }

    private StatisticDataKey() {
        // Private constructor
    }

    public DeviceId deviceId() {
        return deviceId;
    }

    public PortNumber portNumber() {
        return portNumber;
    }

    public Type type() {
        return type;
    }

    public static Builder builder() {
        return new Builder();
    }

    @Override
    public boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof StatisticDataKey)) {
            return false;
        }
        final StatisticDataKey other = (StatisticDataKey) obj;
        return Objects.equals(this.deviceId, other.deviceId) &&
                Objects.equals(this.portNumber, other.portNumber) &&
                this.type == other.type;
    }

    @Override
    public int hashCode() {
        return Objects.hash(deviceId, portNumber, type);
    }

    @Override
    public String toString() {
        return MoreObjects.toStringHelper(getClass())
                .add("deviceId", deviceId)
                .add("portNumber", portNumber)
                .add("type", type)
                .toString();
    }

    public static class Builder {
        private StatisticDataKey data = new StatisticDataKey();

        public Builder withDeviceId(DeviceId deviceId) {
            data.deviceId = deviceId;
            return this;
        }

        public Builder withPortNumber(PortNumber portNumber) {
            data.portNumber = portNumber;
            return this;
        }

        public Builder withType(Type type) {
            data.type = type;
            return this;
        }

        public StatisticDataKey build() {
            return data;
        }
    }
}
