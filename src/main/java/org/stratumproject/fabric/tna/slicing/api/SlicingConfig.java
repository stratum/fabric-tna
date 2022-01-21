// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package org.stratumproject.fabric.tna.slicing.api;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import org.onosproject.core.ApplicationId;
import org.onosproject.net.config.Config;
import org.onosproject.net.config.ConfigException;
import org.onosproject.net.config.InvalidFieldException;

import java.util.Collection;
import java.util.List;
import java.util.Map;

import static java.lang.String.format;

/**
 * Configuration for slicing.
 * <p>
 * Example:
 * <pre>
 * {
 *   "apps": {
 *     "org.stratumproject.fabric-tna": {
 *       "slicing": {
 *         "slices": {
 *           "0": {
 *             "name": "Default",
 *             "tcs": {
 *               "REAL_TIME": {
 *                 "queueId": 1,
 *                 "isSystemTc": true
 *               }
 *             }
 *           },
 *           "1": {
 *             "name": "P4-UPF",
 *             "tcs": {
 *               "CONTROL": {
 *                 "queueId": 2,
 *                 "maxRateBps": "2000000"
 *               },
 *               "REAL_TIME": {
 *                 "queueId": 3,
 *                 "maxRateBps": "50000000"
 *               },
 *               "ELASTIC": {
 *                 "queueId": 4,
 *                 "gminRateBps": "10000000"
 *               }
 *             }
 *           },
 *           "2": {
 *             "name": "BESS-UPF",
 *             "tcs": {
 *               "ELASTIC": {
 *                 "queueId": 5
 *               }
 *             }
 *           }
 *         }
 *       }
 *     }
 *   }
 * }
 * </pre>
 */
public class SlicingConfig extends Config<ApplicationId> {

    private static final String SLICES = "slices";
    private static final String TCS = "tcs";
    private static final String NAME = "name";
    private static final String QUEUE_ID = "queueId";
    private static final String IS_SYSTEM_TC = "isSystemTc";
    private static final String MAX_RATE_BPS = "maxRateBps";
    private static final String GMIN_RATE_BPS = "gminRateBps";

    private static final long DEFAULT_MAX_RATE_BPS = TrafficClassDescription.UNLIMITED_BPS;
    private static final long DEFAULT_GMIN_RATE_BPS = 0;
    private static final boolean DEFAULT_IS_SYSTEM_TC = false;

    @Override
    public boolean isValid() {
        if (!(hasOnlyFields(object, SLICES))) {
            return false;
        }

        for (JsonNode sliceNode : object.path(SLICES)) {
            if (!(hasOnlyFields((ObjectNode) sliceNode, NAME, TCS) &&
                    hasFields((ObjectNode) sliceNode, NAME) &&
                    isString((ObjectNode) sliceNode, NAME, FieldPresence.MANDATORY))) {
                return false;
            }

            for (JsonNode tcNode : sliceNode.path(TCS)) {
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
        }

        try {
            var slices = slices();
            if (slices.isEmpty()) {
                throw new InvalidFieldException(SLICES, "At least one slice should be specified");
            }

            var systemTcsCount = 0;
            for (SliceDescription sliceConfig : slices) {
                for (TrafficClassDescription tcDescription : sliceConfig.tcDescriptions()) {
                    if (tcDescription.isSystemTc()) {
                        systemTcsCount++;
                    }
                }
            }
            if (systemTcsCount == 0) {
                throw new InvalidFieldException(SLICES, format(
                        "At least one traffic class should be set as the system one (%s=true)",
                        IS_SYSTEM_TC));
            }
            if (systemTcsCount > 1) {
                throw new InvalidFieldException(SLICES,
                        "Too many traffic classes are set as the system one, only one is allowed");
            }
        } catch (ConfigException e) {
            throw new InvalidFieldException(SLICES, e);
        }

        return true;
    }

    /**
     * Returns the collection of slice descriptions defined in this config.
     *
     * @return collection of slice descriptions
     * @throws ConfigException if the config is invalid
     */
    public Collection<SliceDescription> slices() throws ConfigException {
        List<SliceDescription> sliceConfigs = Lists.newArrayList();
        var jsonSlices = object.path(SLICES).fields();
        while (jsonSlices.hasNext()) {
            var jsonSlice = jsonSlices.next();
            SliceId sliceId;
            try {
                sliceId = SliceId.of(Integer.parseInt(jsonSlice.getKey()));
            } catch (IllegalArgumentException e) {
                // This is catching also NumberFormatException (subclass of
                // IllegalArgumentException) thrown by parseInt.
                throw new ConfigException(format(
                        "\"%s\" is not a valid slice ID", jsonSlice.getKey()), e);
            }
            sliceConfigs.add(slice(sliceId));
        }
        return sliceConfigs;
    }

    /**
     * Returns the description of the specific slice with the given ID, or null
     * if such slice is not defined in this config.
     *
     * @param sliceId slice ID
     * @return slice description
     * @throws ConfigException if the config is invalid
     */
    public SliceDescription slice(SliceId sliceId) throws ConfigException {
        var sliceNode = object.path(SLICES).path(sliceId.toString());
        if (sliceNode.isMissingNode()) {
            return null;
        }

        var name = sliceNode.path(NAME).asText();
        if (name.isEmpty()) {
            throw new ConfigException(format(
                    "Slice %s must have a valid name", sliceId));
        }

        Map<TrafficClass, TrafficClassDescription> tcDescriptions = Maps.newHashMap();
        var tcDescriptionFields = sliceNode.path(TCS).fields();
        while (tcDescriptionFields.hasNext()) {
            var tcDescriptionField = tcDescriptionFields.next();
            var tcName = tcDescriptionField.getKey();
            TrafficClass tc;
            try {
                tc = TrafficClass.valueOf(tcName);
            } catch (IllegalArgumentException e) {
                throw new ConfigException(format(
                        "\"%s\" is not a valid traffic class for slice %s", tcName, sliceId), e);
            }
            if (tc.equals(TrafficClass.BEST_EFFORT)) {
                throw new ConfigException("BEST_EFFORT is implicit for all slices and cannot be configured");
            }
            tcDescriptions.put(tc, tcDescription(sliceId, tc));
        }

        return new SliceDescription(sliceId, name, tcDescriptions);
    }

    /**
     * Returns the description of the given traffic class whitin the given
     * slice, or null if missing from this config.
     *
     * @param sliceId slice ID
     * @param tc      traffic class
     * @return traffic class description
     * @throws ConfigException if the config is invalid
     */
    public TrafficClassDescription tcDescription(SliceId sliceId, TrafficClass tc) throws ConfigException {
        var tcNode = object.path(SLICES)
                .path(sliceId.toString())
                .path(TCS)
                .path(tc.name());
        if (tcNode.isMissingNode()) {
            return null;
        }

        QueueId queueId;
        try {
            queueId = QueueId.of(tcNode.path(QUEUE_ID).asInt());
        } catch (IllegalArgumentException e) {
            throw new ConfigException(format(
                    "\"%s\" is not a valid queue ID for traffic class %s of slice %s",
                    tcNode.path(QUEUE_ID).asText(), tc, sliceId), e);
        }

        var maxRateBps = tcNode.path(MAX_RATE_BPS).asLong(DEFAULT_MAX_RATE_BPS);
        var gminRateBps = tcNode.path(GMIN_RATE_BPS).asLong(DEFAULT_GMIN_RATE_BPS);
        var isSystemTc = tcNode.path(IS_SYSTEM_TC).asBoolean(DEFAULT_IS_SYSTEM_TC);

        return new TrafficClassDescription(tc, queueId, maxRateBps, gminRateBps, isSystemTc);
    }
}
