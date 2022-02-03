// Copyright 2018-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0

package org.stratumproject.fabric.tna.behaviour;

import org.onosproject.net.DeviceId;
import org.onosproject.net.driver.AbstractHandlerBehaviour;
import org.onosproject.net.driver.DriverHandler;
import org.onosproject.net.pi.model.PiPipeconf;
import org.onosproject.net.pi.service.PiPipeconfService;
import org.slf4j.Logger;

import java.util.Optional;

import static com.google.common.base.Preconditions.checkNotNull;
import static java.lang.String.format;
import static org.slf4j.LoggerFactory.getLogger;

/**
 * Abstract implementation of HandlerBehaviour for the fabric-tna pipeconf
 * behaviors.
 * <p>
 * All sub-classes must implement a default constructor, used by the abstract
 * projectable model (i.e., {@link org.onosproject.net.Device#as(Class)}.
 */
public abstract class AbstractFabricHandlerBehavior extends AbstractHandlerBehaviour {

    protected final Logger log = getLogger(getClass());

    protected FabricCapabilities capabilities;
    protected PiPipeconf pipeconf;

    /**
     * Creates a new instance of this behavior with the given capabilities.
     * Note: this constructor should be invoked only by other classes of this
     * package that can retrieve capabilities on their own.
     * <p>
     * When using the abstract projectable model (i.e., {@link
     * org.onosproject.net.Device#as(Class)}, capabilities will be set by the
     * driver manager when calling {@link #setHandler(DriverHandler)})
     *
     * @param capabilities capabilities
     */
    protected AbstractFabricHandlerBehavior(FabricCapabilities capabilities) {
        this.capabilities = capabilities;
    }

    /**
     * Creates a new instance of this behavior with the given capabilities and pipeconf.
     * Note: this constructor should be invoked only by other classes of this
     * package that can retrieve capabilities on their own.
     * <p>
     * When using the abstract projectable model (i.e., {@link
     * org.onosproject.net.Device#as(Class)}, capabilities and pipeconf will be set by the
     * driver manager when calling {@link #setHandler(DriverHandler)})
     *
     * @param capabilities capabilities
     * @param pipeconf pipeconf
     */
    protected AbstractFabricHandlerBehavior(FabricCapabilities capabilities, PiPipeconf pipeconf) {
        this.capabilities = capabilities;
        this.pipeconf = pipeconf;
    }

    /**
     * Create a new instance of this behaviour. Used by the abstract projectable
     * model (i.e., {@link org.onosproject.net.Device#as(Class)}.
     */
    public AbstractFabricHandlerBehavior() {
        // Do nothing
    }

    @Override
    public void setHandler(DriverHandler handler) {
        super.setHandler(handler);
        final PiPipeconfService pipeconfService = handler().get(PiPipeconfService.class);
        setCapabilitiesFromHandler(handler().data().deviceId(), pipeconfService);
    }

    private void setCapabilitiesFromHandler(
            DeviceId deviceId, PiPipeconfService pipeconfService) {
        checkNotNull(deviceId);
        checkNotNull(pipeconfService);
        // Get pipeconf and device capabilities.
        Optional<PiPipeconf> pipeconfOptional = pipeconfService.getPipeconf(deviceId);
        if (pipeconfOptional.isEmpty()) {
            throw new IllegalStateException(format(
                    "Pipeconf for '%s' is not registered ", deviceId));
        }
        this.pipeconf = pipeconfOptional.get();
        this.capabilities = new FabricCapabilities(this.pipeconf);
    }
}
