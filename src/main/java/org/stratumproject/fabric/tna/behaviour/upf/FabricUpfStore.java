// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.behaviour.upf;

import org.onosproject.net.behaviour.upf.PacketDetectionRule;
import org.onlab.packet.Ip4Address;
import org.onlab.util.ImmutableByteSequence;

import java.util.Map;
import java.util.Set;

/**
 * Stores state required for translation of UPF entities to pipeline-specific ones.
 */
public interface FabricUpfStore {
    /**
     * Clear all state associated with translation.
     */
    void reset();

    /**
     * Returns the farIdMap.
     *
     * @return the farIdMap.
     */
    Map<UpfRuleIdentifier, Integer> getFarIdMap();

    /**
     * Get a globally unique integer identifier for the FAR identified by the given (Session ID, Far
     * ID) pair.
     *
     * @param farIdPair a RuleIdentifier instance uniquely identifying the FAR
     * @return A globally unique integer identifier
     */
    int globalFarIdOf(UpfRuleIdentifier farIdPair);

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
     * Get the corresponding PFCP session ID and session-local FAR ID from a globally unique FAR ID,
     * or return null if no such mapping is found.
     *
     * @param globalFarId globally unique FAR ID
     * @return the corresponding PFCP session ID and session-local FAR ID, as a RuleIdentifier
     */
    UpfRuleIdentifier localFarIdOf(int globalFarId);

    /**
     * Get the corresponding queue Id from scheduling priority.
     *
     * @param schedulingPriority QCI scheduling priority
     * @return the corresponding queue ID
     */
    String queueIdOf(int schedulingPriority);

    /**
     * Get the corresponding queue Id from scheduling priority.
     *
     * @param queueId Tofino queue Id
     * @return the corresponding scheduling priroity
    */
    String schedulingPriorityOf(int queueId);

    /**
     * Stores the mapping between FAR ID and UE address as defined by the given PDR.
     *
     * @param pdr PDR
     */
    void learnFarIdToUeAddrs(PacketDetectionRule pdr);

    /**
     * Returns true if the given FAR IDs is known to be a buffering one.
     *
     * @param farId FAR ID
     * @return boolean
     */
    boolean isFarIdBuffering(UpfRuleIdentifier farId);

    /**
     * Learns the given FAR ID as being a buffering one.
     *
     * @param farId FAR ID
     */
    void learBufferingFarId(UpfRuleIdentifier farId);

    /**
     * Forgets the given FAR ID as being a buffering one.
     *
     * @param farId FAR ID
     */
    void forgetBufferingFarId(UpfRuleIdentifier farId);

    /**
     * Returns the set of UE addresses associated with the given FAR ID.
     *
     * @param farId FAR ID
     * @return Set of Ip4Address
     */
    Set<Ip4Address> ueAddrsOfFarId(UpfRuleIdentifier farId);

    /**
     * Removes the given UE address from the FAR ID to UE address map.
     * @param ueAddr UE address
     */
    void forgetUeAddr(Ip4Address ueAddr);

    /**
     * Returns the set of known buffering FAR IDs.
     * @return set
     */
    Set<UpfRuleIdentifier> getBufferFarIds();

    /**
     * Returns the FAR ID to UE addresses map.
     *
     * @return map
     */
    Map<UpfRuleIdentifier, Set<Ip4Address>> getFarIdToUeAddrs();
}
