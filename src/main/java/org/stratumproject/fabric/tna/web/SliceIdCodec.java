// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package org.stratumproject.fabric.tna.web;

import com.fasterxml.jackson.databind.node.ObjectNode;
import org.onosproject.codec.CodecContext;
import org.onosproject.codec.JsonCodec;
import org.stratumproject.fabric.tna.slicing.api.SliceId;

import static org.onlab.util.Tools.nullIsIllegal;

/**
 * Codec for SliceId.
 */
public final class SliceIdCodec extends JsonCodec<SliceId> {
    //JSON field name
    public static final String SLICE_ID = "SliceId";
    public static final String MISSING_MEMBER_MESSAGE = " member is required";

    @Override
    public ObjectNode encode(SliceId sliceId, CodecContext context) {
        ObjectNode result = context.mapper().createObjectNode();

        result.put(SLICE_ID, sliceId.id());

        return result;
    }

    @Override
    public SliceId decode(ObjectNode json, CodecContext context) {
        ObjectNode node = nullIsIllegal(get(json, SLICE_ID), SLICE_ID + MISSING_MEMBER_MESSAGE);
        // We cannot apply asInt() directly because it will return 0 on fail situation
        // while 0 is a valid SliceId
        int id = Integer.parseInt(node.asText());

        return SliceId.of(id);
    }
}
