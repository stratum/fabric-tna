// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package org.stratumproject.fabric.tna.slicing.api;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.google.common.collect.Lists;
import org.onosproject.net.config.Config;
import org.onosproject.net.config.ConfigException;
import org.onosproject.net.config.InvalidFieldException;

import java.util.Collection;
import java.util.List;

import static java.lang.String.format;

/**
 * Configuration for slicing.
 * <p>
 * Example:
 * <pre>
 * {
 *   "slices": {
 *     "0": {
 *       "basic": {
 *         "name": "Default",
 *         "tcs": {
 *           "REAL_TIME": {
 *             "queueId": 1,
 *             "isSystemTc": true
 *           }
 *         }
 *       }
 *     },
 *     "1": {
 *       "basic": {
 *         "name": "P4-UPF",
 *         "tcs": {
 *           "CONTROL": {
 *             "queueId": 2,
 *             "maxRateBps": "2000000"
 *           },
 *           "REAL_TIME": {
 *             "queueId": 3,
 *             "maxRateBps": "50000000"
 *           },
 *           "ELASTIC": {
 *             "queueId": 4,
 *             "gminRateBps": "10000000"
 *           }
 *         }
 *       }
 *     },
 *     "2": {
 *       "basic": {
 *         "name": "BESS-UPF",
 *         "tcs": {
 *           "ELASTIC": {
 *             "queueId": 5
 *           }
 *         }
 *       }
 *     }
 *   }
 * }
 * </pre>
 */
public class BasicSliceConfig extends Config<SliceId> {

    public static final String CONFIG_KEY = "basic";

    private static final String TCS = "tcs";
    private static final String NAME = "name";
    private static final String QUEUE_ID = "queueId";
    private static final String IS_SYSTEM_TC = "isSystemTc";
    private static final String MAX_RATE_BPS = "maxRateBps";
    private static final String GMIN_RATE_BPS = "gminRateBps";

    private static final long DEFAULT_MAX_RATE_BPS = TrafficClassDescription.UNLIMITED_BPS;
    private static final long DEFAULT_GMIN_RATE_BPS = 0;
    private static final boolean DEFAULT_IS_SYSTEM_TC = false;

    // FIXME: optain ID here, can we parse the object key? Look at InterfaceConfig.

    @Override
    public boolean isValid() {

        if (!(hasOnlyFields(object, NAME, TCS) &&
                hasFields(object, NAME) &&
                isString(object, NAME, FieldPresence.MANDATORY))) {
            return false;
        }

        for (JsonNode tcNode : object.path(TCS)) {
            if (!(hasOnlyFields((ObjectNode) tcNode, QUEUE_ID, MAX_RATE_BPS, GMIN_RATE_BPS, IS_SYSTEM_TC) &&
                    hasFields((ObjectNode) tcNode, QUEUE_ID) &&
                    isIntegralNumber((ObjectNode) tcNode, QUEUE_ID, FieldPresence.MANDATORY,
                            QueueId.MIN, QueueId.MAX) &&
                    isIntegralNumber((ObjectNode) tcNode, MAX_RATE_BPS, FieldPresence.OPTIONAL, 0,
                            TrafficClassDescription.UNLIMITED_BPS)) &&
                    isIntegralNumber((ObjectNode) tcNode, GMIN_RATE_BPS, FieldPresence.OPTIONAL,
                            0, TrafficClassDescription.UNLIMITED_BPS) &&
                    isBoolean((ObjectNode) tcNode, IS_SYSTEM_TC, FieldPresence.OPTIONAL)) {
                return false;
                }
            }

        try {
            if (tcDescriptions().isEmpty()) {
                throw new InvalidFieldException(TCS, "At least one traffic class should be specified");
            }
        } catch (ConfigException e) {
            throw new InvalidFieldException(TCS, e);
        }

        return true;
    }

    /**
     * Returns the name of this slice.
     *
     * @return name
     * @throws ConfigException if the config is invalid
     */
    public String name() throws ConfigException {
        var name = object.path(NAME).asText();
        if (name.isEmpty()) {
            throw new ConfigException("Slice must have a valid name");
        }
        return name;
    }

    /**
     * Returns the traffic classes defined for this slice.
     *
     * @return traffic classes description
     * @throws ConfigException if the config is invalid
     */
    public Collection<TrafficClassDescription> tcDescriptions() throws ConfigException {
        List<TrafficClassDescription> tcDescriptions = Lists.newArrayList();
        var tcFields = object.path(TCS).fields();
        while (tcFields.hasNext()) {
            var tcDescriptionField = tcFields.next();
            var tcName = tcDescriptionField.getKey();
            TrafficClass tc;
            try {
                tc = TrafficClass.valueOf(tcName);
            } catch (IllegalArgumentException e) {
                throw new ConfigException(format(
                        "\"%s\" is not a valid traffic class", tcName), e);
            }
            tcDescriptions.add(tcDescription(tc));
        }
        return tcDescriptions;
    }

    /**
     * Returns the description of the given traffic class within this slice, or
     * null if not present.
     *
     * @param tc traffic class
     * @return traffic class description
     * @throws ConfigException if the config is invalid
     */
    public TrafficClassDescription tcDescription(TrafficClass tc) throws ConfigException {
        var tcNode = object.path(TCS).path(tc.name());
        if (tcNode.isMissingNode()) {
            return null;
        }

        if (tc.equals(TrafficClass.BEST_EFFORT)) {
            throw new ConfigException("BEST_EFFORT is implicit for all slices and cannot be configured");
        }

        QueueId queueId;
        try {
            queueId = QueueId.of(tcNode.path(QUEUE_ID).asInt());
        } catch (IllegalArgumentException e) {
            throw new ConfigException(format(
                    "\"%s\" is not a valid queue ID for traffic class %s",
                    tcNode.path(QUEUE_ID).asText(), tc), e);
        }

        var maxRateBps = tcNode.path(MAX_RATE_BPS).asLong(DEFAULT_MAX_RATE_BPS);
        var gminRateBps = tcNode.path(GMIN_RATE_BPS).asLong(DEFAULT_GMIN_RATE_BPS);
        var isSystemTc = tcNode.path(IS_SYSTEM_TC).asBoolean(DEFAULT_IS_SYSTEM_TC);

        return new TrafficClassDescription(tc, queueId, maxRateBps, gminRateBps, isSystemTc);
    }
}
