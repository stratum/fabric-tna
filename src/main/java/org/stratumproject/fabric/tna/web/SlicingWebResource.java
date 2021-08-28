// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package org.stratumproject.fabric.tna.web;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.onosproject.rest.AbstractWebResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.stratumproject.fabric.tna.slicing.api.SliceId;
import org.stratumproject.fabric.tna.slicing.api.SlicingService;
import org.stratumproject.fabric.tna.slicing.api.TrafficClass;

import java.util.Set;

import javax.ws.rs.Consumes;
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
        ObjectNode root = mapper().createObjectNode();
        ArrayNode array = root.putArray("Slices");

        result.forEach(id -> array.add(codec(SliceId.class).encode(id, this)));

        return Response.ok(root).build();
    }

    /**
     * Add a new slice.
     *
     * @param sliceId id of slice
     * @return 200 ok and result message
     */
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Path("slice/{sliceId}")
    public Response addSlice(@PathParam("sliceId") int sliceId) {
        boolean result = slicingService.addSlice(SliceId.of(sliceId));

        Response response;
        if (result) {
            response = Response.ok().build();
        } else {
            response = Response.serverError().build();
        }

        return response;
    }

    /**
     * Remove an existing slice.
     *
     * @param sliceId id of slice
     * @return 200 ok and result message
     */
    @DELETE
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Path("slice/{sliceId}")
    public Response removeSlice(@PathParam("sliceId") int sliceId) {
        boolean result =  slicingService.removeSlice(SliceId.of(sliceId));

        Response response;
        if (result) {
            response = Response.ok().build();
        } else {
            response = Response.serverError().build();
        }

        return response;
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
        ObjectNode root = mapper().createObjectNode();
        ArrayNode array = root.putArray("TrafficClasses");

        result.forEach(tc -> array.add(codec(TrafficClass.class).encode(tc, this)));

        return Response.ok(root).build();
    }

    /**
     * Add a traffic class to a slice.
     *
     * @param sliceId id of slice
     * @param tc traffic class to be added
     * @return 200 ok and result message
     */
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Path("tc/{sliceId}/{tc}")
    public Response addTc(@PathParam("sliceId") int sliceId, @PathParam("tc") String tc) {
        boolean result = slicingService.addTrafficClass(SliceId.of(sliceId), TrafficClass.valueOf(tc));

        Response response;
        if (result) {
            response = Response.ok().build();
        } else {
            response = Response.serverError().build();
        }

        return response;
    }

    /**
     * Remove a traffic class from a slice.
     *
     * @param sliceId id of slice
     * @param tc traffic class to be removed
     * @return 200 ok and result message
     */
    @DELETE
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Path("tc/{sliceId}/{tc}")
    public Response removeTc(@PathParam("sliceId") int sliceId, @PathParam("tc") String tc) {
        boolean result = slicingService.removeTrafficClass(SliceId.of(sliceId), TrafficClass.valueOf(tc));

        Response response;
        if (result) {
            response = Response.ok().build();
        } else {
            response = Response.serverError().build();
        }

        return response;
    }
}