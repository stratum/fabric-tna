// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.behaviour.upf;

import org.onlab.util.ImmutableByteSequence;

import java.util.Map;

/**
 * Stores state required for translation of UPF entities to pipeline-specific ones.
 */
public interface FabricUpfStore {
    /**
     * Clear all state associated with translation.
     */
    void reset();

    /**
     * Returns the reverseFarIdMap.
     *
     * @return the farIdMap.
     */
    Map<Integer, UpfRuleIdentifier> getReverseFarIdMap();

    /**
     * Get a globally unique integer identifier for the FAR identified by the given (Session ID, Far
     * ID) pair.
     *
     * @param farIdPair a RuleIdentifier instance uniquely identifying the FAR
     * @return A globally unique integer identifier
     */
    int globalFarIdOf(UpfRuleIdentifier farIdPair);

    /**
     * Remove the global far id from the system.
     *
     * @param farIdPair a RuleIdentifier instance uniquely identifying the FAR
     * @return A globally unique integer identifier
     */
    int removeGlobalFarId(UpfRuleIdentifier farIdPair);

    /**
     * Get a globally unique integer identifier for the FAR identified by the given (Session ID, Far
     * ID) pair.
     *
     * @param pfcpSessionId     The ID of the PFCP session that produced the FAR ID.
     * @param sessionLocalFarId The FAR ID.
     * @return A globally unique integer identifier
     */
    int globalFarIdOf(ImmutableByteSequence pfcpSessionId, int sessionLocalFarId);

    /**
     * Remove the global far id from the system.
     *
     * @param pfcpSessionId     The ID of the PFCP session that produced the FAR ID.
     * @param sessionLocalFarId The FAR ID.
     * @return A globally unique integer identifier
     */
    int removeGlobalFarId(ImmutableByteSequence pfcpSessionId, int sessionLocalFarId);

    /**
     * Get the corresponding PFCP session ID and session-local FAR ID from a globally unique FAR ID,
     * or return null if no such mapping is found.
     *
     * @param globalFarId globally unique FAR ID
     * @return the corresponding PFCP session ID and session-local FAR ID, as a RuleIdentifier
     */
    UpfRuleIdentifier localFarIdOf(int globalFarId);
}
