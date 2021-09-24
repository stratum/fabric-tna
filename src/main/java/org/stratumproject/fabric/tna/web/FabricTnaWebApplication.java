// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package org.stratumproject.fabric.tna.web;

import org.onlab.rest.AbstractWebApplication;

import java.util.Set;

/**
 * Fabric-tna REST API.
 */
public class FabricTnaWebApplication extends AbstractWebApplication {
    @Override
    public Set<Class<?>> getClasses() {
        return getClasses(
            SlicingWebResource.class,
            SlicingExceptionMapper.class
        );
    }
}
