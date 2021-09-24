// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package org.stratumproject.fabric.tna.web;

import javax.ws.rs.core.Response;
import javax.ws.rs.ext.Provider;

import org.onlab.rest.exceptions.AbstractMapper;
import org.onosproject.net.slicing.SlicingException;

/**
 * Mapper for slicing exception to the BAD_REQUEST response code.
 */
@Provider
public class SlicingExceptionMapper extends AbstractMapper<SlicingException> {
    @Override
    protected Response.Status responseStatus() {
        return Response.Status.BAD_REQUEST;
    }
}