// Copyright 2018-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0

package org.stratumproject.fabric.tna.behaviour;

import org.onosproject.net.pi.model.PiPipeconf;
import org.slf4j.Logger;
import org.stratumproject.fabric.tna.slicing.api.MeterColor;

import java.util.Optional;

import static com.google.common.base.Preconditions.checkNotNull;
import static org.slf4j.LoggerFactory.getLogger;
import static org.stratumproject.fabric.tna.Constants.BMV2_COLOR_RED;
import static org.stratumproject.fabric.tna.Constants.PORT_CPU_BMV2;
import static org.stratumproject.fabric.tna.Constants.TNA;
import static org.stratumproject.fabric.tna.Constants.V1MODEL;
import static org.stratumproject.fabric.tna.Constants.PORT_CPU;
import static org.stratumproject.fabric.tna.behaviour.P4InfoConstants.FABRIC_INGRESS_UPF_UPLINK_SESSIONS;

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

    public boolean isArchV1model() {
        return pipeconf.pipelineModel().architecture()
                .map(a -> a.equals(V1MODEL))
                .orElse(false);
    }

    public boolean isArchTna() {
        return pipeconf.pipelineModel().architecture()
                .map(a -> a.equals(TNA))
                .orElse(false);
    }

    public int getMeterColor(MeterColor color) {
        if (isArchV1model() && color == MeterColor.RED) {
            return BMV2_COLOR_RED;
        } else {
            return color.toInt();
        }
    }

    public Optional<Long> cpuPort() {
        return isArchTna() ? Optional.of(PORT_CPU) : Optional.of(PORT_CPU_BMV2);
    }

    /**
     * Returns true if the pipeconf supports UPF capabilities, false otherwise.
     *
     * @return boolean
     */
    public boolean supportUpf() {
        return pipeconf.pipelineModel()
                .table(FABRIC_INGRESS_UPF_UPLINK_SESSIONS)
                .isPresent();
    }

    public boolean supportDoubleVlanTerm() {
        // TODO: re-enable support for double-vlan
        // FIXME: next_vlan has been moved to pre_next
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
