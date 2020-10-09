// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0

package org.stratumproject.fabric.tna.behaviour.traceable;

import org.onosproject.net.DataPlaneEntity;
import org.onosproject.net.PipelineTraceableInput;
import org.onosproject.net.PipelineTraceableOutput;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.pi.runtime.PiTableEntry;

/**
 * Representation of a traceable control block for fabric-tna.
 * It is important to note that there is not a 1-1 mapping between
 * a table and a control block.
 */
interface PipelineTraceableCtrl {

    /**
     * Apply the given control block to the input data.
     *
     * @param input the traceable input
     * @return the traceable output created by this control block
     */
    PipelineTraceableOutput apply(PipelineTraceableInput input);

    /**
     * Match the data plane entity against the input packet returning
     * the corresponding pi table entry.
     *
     * @param packet the input packet
     * @param dataPlaneEntity the data plane entity
     * @return the matched table entry otherwise null
     */
    PiTableEntry matchTables(TrafficSelector packet, DataPlaneEntity dataPlaneEntity);

    /**
     * Augment the packet introducing the hidden fields needed for the flow translation.
     * The augmentation depends on the table associated with the data plane entity and
     * on the metadata fields.
     *
     * @param packet the input packet
     * @param metadata the metadata fields
     * @param dataPlaneEntity the data plane entity
     * @return the augmented representation of the input packet
     */
    TrafficSelector augmentPacket(TrafficSelector packet, FabricTraceableMetadata metadata,
                                  DataPlaneEntity dataPlaneEntity);

    /**
     * Apply the pi table entry on the fabric traceable metadata.
     *
     * @param metadataBuilder the metadata builder
     * @param piTableEntry the pi table entry
     */
    void applyTables(FabricTraceableMetadata.Builder metadataBuilder, PiTableEntry piTableEntry);

}
