// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package org.stratumproject.fabric.tna.web;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.onosproject.rest.AbstractWebResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.stratumproject.fabric.tna.slicing.QueueStoreValue;
import org.stratumproject.fabric.tna.slicing.api.QueueId;
import org.stratumproject.fabric.tna.slicing.api.SliceId;
import org.stratumproject.fabric.tna.slicing.api.SlicingAdminService;
import org.stratumproject.fabric.tna.slicing.api.SlicingService;
import org.stratumproject.fabric.tna.slicing.api.TrafficClass;
import org.stratumproject.fabric.tna.slicing.SliceStoreKey;

import java.util.Set;
import java.util.Map;

import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.POST;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

/**
 * Query, add and remove Slices, TCs and Queues.
 */
@Path("slicing")
public class SlicingWebResource extends AbstractWebResource {
    private static Logger log = LoggerFactory.getLogger(SlicingWebResource.class);
    private SlicingService slicingService = getService(SlicingService.class);
    private SlicingAdminService slicingAdminService = getService(SlicingAdminService.class);
    private ObjectMapper mapper = new ObjectMapper();

    /**
     * Get all values present in the queue store.
     *
     * @return 200 ok and a collection of Queue Store Value.
     */
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Path("queue/store")
    public Response getQueueStore() {
        Map<QueueId, QueueStoreValue> result = slicingAdminService.getQueueStore();

        return Response.ok(encodeQueueStore(result)).build();
    }

    /**
     * Reserve a queue.
     *
     * @param queueId id of queue
     * @param tc traffic class
     * @return 200 ok and reserve message
     */
    @POST
    @Produces(MediaType.APPLICATION_JSON)
    @Path("queue/{queueId}/{tc}")
    public Response reserveQueue(@PathParam("queueId") int queueId, @PathParam("tc") String tc) {
        boolean result = slicingAdminService.reserveQueue(QueueId.of(queueId), TrafficClass.valueOf(tc));

        String message;
        if (result) {
            message = String.format("Queue %s reserved for TC %s", queueId, tc);
        } else {
            message = String.format("Failed to reserve queue %s for TC %s", queueId, tc);
        }

        return Response.ok(message).build();
    }

    /**
     * Release a queue.
     *
     * @param queueId id of the queue
     * @return 200 ok and release message
     */
    @DELETE
    @Produces(MediaType.APPLICATION_JSON)
    @Path("queue/{queueId}")
    public Response releaseQueue(@PathParam("queueId") int queueId) {
        boolean result = slicingAdminService.releaseQueue(QueueId.of(queueId));

        String message;
        if (result) {
            message = String.format("Queue %s released", queueId);
        } else {
            message = String.format("Failed to release queue %s", queueId);
        }

        return Response.ok(message).build();
    }

    /**
     * Get all slices.
     *
     * @return 200 ok and a collection of Slice ID
     */
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Path("slice")
    public Response getSlice() {
        Set<SliceId> result = slicingService.getSlices();

        return Response.ok(encodeSlice(result)).build();
    }

    /**
     * Get all values present in the slice store.
     *
     * @return 200 ok and a collection of Slice Store value
     */
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Path("slice/store")
    public Response getSliceStore() {
        Map<SliceStoreKey, QueueId> result = slicingAdminService.getSliceStore();

        return Response.ok(encodeSliceStore(result)).build();
    }

    /**
     * Add a new slice.
     *
     * @param sliceId id of slice
     * @return 200 ok and result message
     */
    @POST
    @Produces(MediaType.APPLICATION_JSON)
    @Path("slice/{sliceId}")
    public Response addSlice(@PathParam("sliceId") int sliceId) {
        boolean result = slicingService.addSlice(SliceId.of(sliceId));

        String message;
        if (result) {
            message = String.format("Slice %s added", sliceId);
        } else {
            message = String.format("Failed to add slice %s", sliceId);
        }

        return Response.ok(message).build();
    }

    /**
     * Remove an existing slice.
     *
     * @param sliceId id of slice
     * @return 200 ok and result message
     */
    @DELETE
    @Produces(MediaType.APPLICATION_JSON)
    @Path("slice/{sliceId}")
    public Response removeSlice(@PathParam("sliceId") int sliceId) {
        boolean result =  slicingService.removeSlice(SliceId.of(sliceId));

        String message;
        if (result) {
            message = String.format("Slice %s removed", sliceId);
        } else {
            message = String.format("Failed to remove slice %s", sliceId);
        }

        return Response.ok(message).build();
    }

    /**
     * Get all traffic class of a slice.
     *
     * @param sliceId id of slice
     * @return 200 ok and a collection of traffic class
     */
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Path("tc/{sliceId}")
    public Response getTc(@PathParam("sliceId") int sliceId) {
        Set<TrafficClass> result = slicingService.getTrafficClasses(SliceId.of(sliceId));

        return Response.ok(encodeTc(result)).build();
    }

    /**
     * Add a traffic class to a slice.
     *
     * @param sliceId id of slice
     * @param tc traffic class to be added
     * @return 200 ok and result message
     */
    @POST
    @Produces(MediaType.APPLICATION_JSON)
    @Path("tc/{sliceId}/{tc}")
    public Response addTc(@PathParam("sliceId") int sliceId, @PathParam("tc") String tc) {
        boolean result = slicingService.addTrafficClass(SliceId.of(sliceId), TrafficClass.valueOf(tc));

        String message;
        if (result) {
            message = String.format("TC %s added to slice %s", tc, sliceId);
        } else {
            message = String.format("Failed to add TC %s to slice %s", tc, sliceId);
        }

        return Response.ok(message).build();
    }

    /**
     * Remove a traffic class from a slice.
     *
     * @param sliceId id of slice
     * @param tc traffic class to be removed
     * @return 200 ok and result message
     */
    @DELETE
    @Produces(MediaType.APPLICATION_JSON)
    @Path("tc/{sliceId}/{tc}")
    public Response removeTc(@PathParam("sliceId") int sliceId, @PathParam("tc") String tc) {
        boolean result = slicingService.removeTrafficClass(SliceId.of(sliceId), TrafficClass.valueOf(tc));

        String message;
        if (result) {
            message = String.format("TC %s removed from slice %s", tc, sliceId);
        } else {
            message = String.format("Failed to remove TC %s from slice %s", tc, sliceId);
        }

        return Response.ok(message).build();
    }

    private ObjectNode encodeQueueStore(Map<QueueId, QueueStoreValue> queueStore) {
        ObjectNode root = mapper.createObjectNode();
        ArrayNode array = root.putArray("QueueStore");

        queueStore.forEach((k, v) -> {
            ObjectNode node = array.addObject();
            node.put("QueueId", k.id());
            node.put("TrafficClass", v.trafficClass().toString());
            node.put("Available", v.available());
        });

        return root;
    }

    private ObjectNode encodeSlice(Set<SliceId> slices) {
        ObjectNode root = mapper.createObjectNode();

        ArrayNode array = root.putArray("SliceId");
        slices.forEach(s -> array.add(s.id()));

        return root;
    }

    private ObjectNode encodeSliceStore(Map<SliceStoreKey, QueueId> sliceStore) {
        ObjectNode root = mapper.createObjectNode();
        ArrayNode array = root.putArray("SliceStore");

        sliceStore.forEach((k, v) -> {
            ObjectNode node = array.addObject();
            node.put("SliceId", k.sliceId().id());
            node.put("TrafficClass", k.trafficClass().toString());
            node.put("QueueId", v.id());
        });

        return root;
    }

    private ObjectNode encodeTc(Set<TrafficClass> tcs) {
        ObjectNode root = mapper.createObjectNode();

        ArrayNode arrayNode = root.putArray("TrafficClass");
        tcs.forEach(tc -> arrayNode.add(tc.toString()));

        return root;
    }
}