// Copyright 2018-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0

package org.stratumproject.fabric.tna.behaviour;

import org.onosproject.net.pi.model.PiPipeconf;
import org.slf4j.Logger;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Optional;

import static com.google.common.base.Preconditions.checkNotNull;
import static org.onosproject.net.pi.model.PiPipeconf.ExtensionType.CPU_PORT_TXT;
import static org.slf4j.LoggerFactory.getLogger;

/**
 * Representation of the capabilities of a given fabric-tna pipeconf.
 */
public class FabricCapabilities {

    private static final String MAVERICKS = "mavericks";
    private static final String MONTARA = "montara";

    private final Logger log = getLogger(getClass());

    private final PiPipeconf pipeconf;

    public FabricCapabilities(PiPipeconf pipeconf) {
        this.pipeconf = checkNotNull(pipeconf);
    }

    public int hwPipeCount() {
        // FIXME: use chip type (or platform name) when Stratum will support
        //  reading that via gNMI. Until then, we need to rely on the
        //  pipeconf name (which prevents us from using chip-independent
        //  pipeconfs).
        final var id = pipeconf.id().toString();
        if (id.contains(MONTARA)) {
            return 2;
        } else if (id.contains(MAVERICKS)) {
            return 4;
        } else {
            log.error("Unable to derive HW pipe count from pipeconf ID: {}", id);
            return 0;
        }
    }

    public boolean hasHashedTable() {
        return pipeconf.pipelineModel()
                .table(P4InfoConstants.FABRIC_INGRESS_NEXT_HASHED).isPresent();
    }

    public Optional<Integer> cpuPort() {
        // This is probably brittle, but needed to dynamically get the CPU port
        // for different platforms.
        if (pipeconf.extension(CPU_PORT_TXT).isEmpty()) {
            log.warn("Missing {} extension in pipeconf {}", CPU_PORT_TXT, pipeconf.id());
            return Optional.empty();
        }
        try {
            final InputStream stream = pipeconf.extension(CPU_PORT_TXT).get();
            final BufferedReader buff = new BufferedReader(
                    new InputStreamReader(stream));
            final String str = buff.readLine();
            buff.close();
            if (str == null) {
                log.error("Empty CPU port file for {}", pipeconf.id());
                return Optional.empty();
            }
            try {
                return Optional.of(Integer.parseInt(str));
            } catch (NumberFormatException e) {
                log.error("Invalid CPU port for {}: {}", pipeconf.id(), str);
                return Optional.empty();
            }
        } catch (IOException e) {
            log.error("Unable to read CPU port file of {}: {}",
                    pipeconf.id(), e.getMessage());
            return Optional.empty();
        }
    }

    public boolean supportDoubleVlanTerm() {
        // TODO: re-enable support for double-vlan
        // if (pipeconf.pipelineModel()
        //         .table(P4InfoConstants.FABRIC_INGRESS_NEXT_NEXT_VLAN).isPresent()) {
        //     return pipeconf.pipelineModel().table(P4InfoConstants.FABRIC_INGRESS_NEXT_NEXT_VLAN)
        //             .get().action(P4InfoConstants.FABRIC_INGRESS_NEXT_SET_DOUBLE_VLAN)
        //             .isPresent();
        // }
        return false;
    }

    // TODO: add fabric-bng profile
    // /**
    //  * Returns true if the pipeconf supports BNG user plane capabilities, false
    //  * otherwise.
    //  *
    //  * @return boolean
    //  */
    // public boolean supportBng() {
    //     return pipeconf.pipelineModel()
    //             .counter(P4InfoConstants.FABRIC_INGRESS_BNG_INGRESS_DOWNSTREAM_C_LINE_RX)
    //             .isPresent();
    // }

    // TODO: add fabric-bng profile
    // /**
    //  * Returns the maximum number of BNG lines supported, or 0 if this pipeconf
    //  * does not support BNG capabilities.
    //  *
    //  * @return maximum number of lines supported
    //  */
    // public long bngMaxLineCount() {
    //     if (!supportBng()) {
    //         return 0;
    //     }
    //     return pipeconf.pipelineModel()
    //             .counter(P4InfoConstants.FABRIC_INGRESS_BNG_INGRESS_DOWNSTREAM_C_LINE_RX)
    //             .orElseThrow().size();
    // }
}
