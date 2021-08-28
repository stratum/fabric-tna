// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package org.stratumproject.fabric.tna.web;

import com.fasterxml.jackson.databind.node.ObjectNode;
import org.onosproject.codec.CodecContext;
import org.onosproject.codec.JsonCodec;
import org.stratumproject.fabric.tna.slicing.api.TrafficClass;

import static org.onlab.util.Tools.nullIsIllegal;

public final class TrafficClassCodec extends JsonCodec<TrafficClass> {
    //JSON field name
    public static final String TRAFFIC_CLASS = "TrafficClass";
    public static final String MISSING_MEMBER_MESSAGE = " member is required";

    @Override
    public ObjectNode encode(TrafficClass tc, CodecContext context) {
        ObjectNode result = context.mapper().createObjectNode();

        result.put(TRAFFIC_CLASS, tc.toString());

        return result;
    }

    @Override
    public TrafficClass decode(ObjectNode json, CodecContext context) {
        ObjectNode node = nullIsIllegal(get(json, TRAFFIC_CLASS), TRAFFIC_CLASS + MISSING_MEMBER_MESSAGE);

        return TrafficClass.valueOf(node.asText());
    }
}
