// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package org.stratumproject.fabric.tna.web;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.rest.AbstractWebResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.stratumproject.fabric.tna.slicing.api.SliceId;
import org.stratumproject.fabric.tna.slicing.api.SlicingService;
import org.stratumproject.fabric.tna.slicing.api.TrafficClass;

import java.io.IOException;
import java.io.InputStream;
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

import static org.onlab.util.Tools.readTreeFromStream;

/**
 * Query, add and remove Slice and TrafficClass.
 */
@Path("slicing")
public class SlicingWebResource extends AbstractWebResource {
    private static Logger log = LoggerFactory.getLogger(SlicingWebResource.class);

    private SlicingService slicingService = getService(SlicingService.class);

    /**
     * Get all slices currently programmed.
     * Pre-defined slice IDs: Default Slice = 0, Mobile Traffic Slice = 15
     *
     * @return 200 ok and a collection of Slice IDs
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
     * Pre-defined slice IDs: Default Slice = 0, Mobile Traffic Slice = 15
     *
     * @param sliceId ID of the slice (DEFAULT_SLICE=0, MOBILE_SLICE=15)
     * @return 200 ok or 400 bad request
     */
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Path("slice/{sliceId}")
    public Response addSlice(@PathParam("sliceId") int sliceId) {
        boolean result = slicingService.addSlice(SliceId.of(sliceId));

        Response response;
        if (result) {
            response = Response.ok().build();
        } else {
            response = Response.status(400).build();
        }

        return response;
    }

    /**
     * Remove an existing slice.
     * Pre-defined slice IDs: Default Slice = 0, Mobile Traffic Slice = 15
     *
     * @param sliceId ID of the slice
     * @return 200 ok or 400 bad request
     */
    @DELETE
    @Path("slice/{sliceId}")
    public Response removeSlice(@PathParam("sliceId") int sliceId) {
        boolean result = slicingService.removeSlice(SliceId.of(sliceId));

        Response response;
        if (result) {
            response = Response.ok().build();
        } else {
            response = Response.status(400).build();
        }

        return response;
    }

    /**
     * Get all traffic class of a slice.
     * Pre-defined slice IDs: Default Slice = 0, Mobile Traffic Slice = 15
     *
     * @param sliceId ID of the slice
     * @return 200 ok and a collection of traffic class or 404 not found if the result is empty
     */
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Path("tc/{sliceId}")
    public Response getTc(@PathParam("sliceId") int sliceId) {
        Set<TrafficClass> result = slicingService.getTrafficClasses(SliceId.of(sliceId));
        ObjectNode root = mapper().createObjectNode();

        Response response;
        if (!result.isEmpty()) {
            ArrayNode array = root.putArray("TrafficClasses");
            result.forEach(tc -> array.add(codec(TrafficClass.class).encode(tc, this)));
            response = Response.ok(root).build();
        } else {
            response = Response.status(404).build();
        }
        return response;
    }

    /**
     * Add a traffic class to a slice.
     * Pre-defined slice IDs: Default Slice = 0, Mobile Traffic Slice = 15
     * Traffic class values: CONTROL, REAL_TIME, ELASTIC, BEST_EFFORT
     *
     * @param sliceId ID of the slice
     * @param tc Traffic class to be added to the given slice
     * @return 200 ok or 400 bad request
     */
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Path("tc/{sliceId}/{tc}")
    public Response addTc(@PathParam("sliceId") int sliceId, @PathParam("tc") String tc) {
        boolean result = slicingService.addTrafficClass(SliceId.of(sliceId), TrafficClass.valueOf(tc));

        Response response;
        if (result) {
            response = Response.ok().build();
        } else {
            response = Response.status(400).build();
        }

        return response;
    }

    /**
     * Get default traffic class given a slice.
     * Pre-defined slice IDs: Default Slice = 0, Mobile Traffic Slice = 15
     *
     * @param sliceId ID of the slice
     * @return 200 ok the default traffic class or 404 not found if the result is empty
     */
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Path("defaulttc/{sliceId}")
    public Response getDefaultTc(@PathParam("sliceId") int sliceId) {
        TrafficClass result = slicingService.getDefaultTrafficClass(SliceId.of(sliceId));

        Response response;
        if (result != null) {
            response = Response.ok(codec(TrafficClass.class).encode(result, this)).build();
        } else {
            response = Response.status(404).build();
        }
        return response;
    }

    /**
     * Set the default traffic class for a slice.
     * Pre-defined slice IDs: Default Slice = 0, Mobile Traffic Slice = 15
     * Traffic class values: CONTROL, REAL_TIME, ELASTIC, BEST_EFFORT
     *
     * @param sliceId ID of the slice
     * @param tc Traffic class to be used as default.
     *           The traffic class must be already part of the given slice.
     * @return 200 ok or 400 bad request
     */
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Path("defaulttc/{sliceId}/{tc}")
    public Response setDefaultTc(@PathParam("sliceId") int sliceId, @PathParam("tc") String tc) {
        boolean result = slicingService.setDefaultTrafficClass(SliceId.of(sliceId), TrafficClass.valueOf(tc));

        Response response;
        if (result) {
            response = Response.ok().build();
        } else {
            response = Response.status(400).build();
        }

        return response;
    }

    /**
     * Remove a traffic class from a slice.
     * Pre-defined slice IDs: Default Slice = 0, Mobile Traffic Slice = 15
     *
     * @param sliceId ID of the slice
     * @param tc Traffic class to be removed
     * @return 200 ok or 400 bad request
     */
    @DELETE
    @Path("tc/{sliceId}/{tc}")
    public Response removeTc(@PathParam("sliceId") int sliceId, @PathParam("tc") String tc) {
        boolean result = slicingService.removeTrafficClass(SliceId.of(sliceId), TrafficClass.valueOf(tc));

        Response response;
        if (result) {
            response = Response.ok().build();
        } else {
            response = Response.status(400).build();
        }

        return response;
    }

    /**
     * Get classifier flows by slice ID and traffic class.
     * Pre-defined slice IDs: Default Slice = 0, Mobile Traffic Slice = 15
     * Traffic class values: CONTROL, REAL_TIME, ELASTIC, BEST_EFFORT
     *
     * @param sliceId ID of the slice
     * @param tc Traffic class
     * @return 200 ok and traffic selectors
     */
    @GET
    @Path("flow/{sliceId}/{tc}")
    public Response getFlow(@PathParam("sliceId") int sliceId, @PathParam("tc") String tc) {
        Set<TrafficSelector> result = slicingService.getFlows(SliceId.of(sliceId), TrafficClass.valueOf(tc));
        ObjectNode root = mapper().createObjectNode();
        ArrayNode array = root.putArray("TrafficSelector");

        result.forEach(id -> array.add(codec(TrafficSelector.class).encode(id, this)));

        return Response.ok(root).build();
    }

    /**
     * Push a classifier flow to classify traffic as part of the given slice and traffic class.
     * Pre-defined slice IDs: Default Slice = 0, Mobile Traffic Slice = 15
     * Traffic class values: CONTROL, REAL_TIME, ELASTIC, BEST_EFFORT
     * Traffic Selector Example:
     *   {
     *     "criteria" : [
     *       {
     *         "type" : "IP_PROTO",
     *         "protocol": 6
     *       },
     *       {
     *         "type": "IPV4_SRC",
     *         "ip": "192.168.1.1/32"
     *       }
     *     ]
     *   }
     *
     * @param sliceId ID of slice
     * @param tc Traffic class
     * @param input JSON stream of traffic selector
     * @return 200 ok or 400 bad request
     */
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Path("flow/{sliceId}/{tc}")
    public Response addFlow(@PathParam("sliceId") int sliceId, @PathParam("tc") String tc, InputStream input) {
        boolean result;
        Response response;
        try {
            ObjectNode jsonTree = readTreeFromStream(mapper(), input);
            TrafficSelector selector = codec(TrafficSelector.class).decode(jsonTree, this);
            result = slicingService.addFlow(selector, SliceId.of(sliceId), TrafficClass.valueOf(tc));
        } catch (IOException ex) {
            throw new IllegalArgumentException(ex);
        }

        if (result) {
            response = Response.ok().build();
        } else {
            response = Response.status(400).build();
        }

        return response;
    }

    /**
     * Remove a classifier flow for the given slice and traffic class.
     * Pre-defined slice IDs: Default Slice = 0, Mobile Traffic Slice = 15
     * Traffic class values: CONTROL, REAL_TIME, ELASTIC, BEST_EFFORT
     *
     * @param sliceId ID of slice
     * @param tc Traffic class
     * @param input JSON stream of traffic selector
     * @return 200 ok or 400 bad request
     */
    @DELETE
    @Consumes(MediaType.APPLICATION_JSON)
    @Path("flow/{sliceId}/{tc}")
    public Response removeFlow(@PathParam("sliceId") int sliceId, @PathParam("tc") String tc, InputStream input) {
        boolean result;
        Response response;
        try {
            ObjectNode jsonTree = readTreeFromStream(mapper(), input);
            TrafficSelector selector = codec(TrafficSelector.class).decode(jsonTree, this);
            result = slicingService.removeFlow(selector, SliceId.of(sliceId), TrafficClass.valueOf(tc));
        } catch (IOException ex) {
            throw new IllegalArgumentException(ex);
        }

        if (result) {
            response = Response.ok().build();
        } else {
            response = Response.status(400).build();
        }

        return response;
    }
}
