// Copyright 2018-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0

package org.stratumproject.fabric.tna.behaviour.pipeliner;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Lists;

import com.google.common.collect.Sets;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.slf4j.Logger;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.onosproject.net.flow.criteria.Criterion.Type.*;
import static org.slf4j.LoggerFactory.getLogger;
import static org.stratumproject.fabric.tna.behaviour.pipeliner.Commons.*;

/**
 * Forwarding function types (FFTs) that can represent a given forwarding
 * objective. Each FFT is defined by a subset of criterion types expected to be
 * found in the selector of the given objective, and, optionally, by their
 * respective values (criterion instances) to match or to mismatch.
 */
public class ForwardingFunctionType {
    enum Type {
        L2_UNICAST,
        L2_BROADCAST,
        L2_BROADCAST_ALIAS,
        IPV4_ROUTING,
        IPV4_ROUTING_MULTICAST,
        IPV6_ROUTING,
        IPV6_ROUTING_MULTICAST,
        MPLS_SEGMENT_ROUTING,
        PSEUDO_WIRE,
        UNKNOWN
    }
    /**
     * L2 unicast.
     */
    public static final ForwardingFunctionType L2_UNICAST = new ForwardingFunctionType(
            Type.L2_UNICAST,
            Sets.newHashSet(VLAN_VID, ETH_DST), // Expected criterion types.
            Collections.emptyList(), // Criteria to match.
            Lists.newArrayList(MATCH_ETH_DST_NONE)); // Criteria NOT to match.

    /**
     * L2 broadcast.
     */
    public static final ForwardingFunctionType L2_BROADCAST = new ForwardingFunctionType(
            Type.L2_BROADCAST,
            Sets.newHashSet(VLAN_VID, ETH_DST),
            Lists.newArrayList(MATCH_ETH_DST_NONE),
            Collections.emptyList());

    public static final ForwardingFunctionType L2_BROADCAST_ALIAS = new ForwardingFunctionType(
            Type.L2_BROADCAST_ALIAS,
            Sets.newHashSet(VLAN_VID),
            Collections.emptyList(),
            Collections.emptyList(),
            L2_BROADCAST); // (Optional) FFT to return if selected.

    /**
     * IPv4 unicast.
     */
    public static final ForwardingFunctionType IPV4_ROUTING = new ForwardingFunctionType(
            Type.IPV4_ROUTING,
            Sets.newHashSet(ETH_TYPE, IPV4_DST),
            Lists.newArrayList(MATCH_ETH_TYPE_IPV4),
            Collections.emptyList());

    /**
     * IPv4 multicast.
     */
    public static final ForwardingFunctionType IPV4_ROUTING_MULTICAST = new ForwardingFunctionType(
            Type.IPV4_ROUTING_MULTICAST,
            Sets.newHashSet(ETH_TYPE, VLAN_VID, IPV4_DST),
            Lists.newArrayList(MATCH_ETH_TYPE_IPV4),
            Collections.emptyList());

    /**
     * IPv6 unicast.
     */
    public static final ForwardingFunctionType IPV6_ROUTING = new ForwardingFunctionType(
            Type.IPV6_ROUTING,
            Sets.newHashSet(ETH_TYPE, IPV6_DST),
            Lists.newArrayList(MATCH_ETH_TYPE_IPV6),
            Collections.emptyList());

    /**
     * IPv6 multicast.
     */
    public static final ForwardingFunctionType IPV6_ROUTING_MULTICAST = new ForwardingFunctionType(
            Type.IPV6_ROUTING_MULTICAST,
            Sets.newHashSet(ETH_TYPE, VLAN_VID, IPV6_DST),
            Lists.newArrayList(MATCH_ETH_TYPE_IPV6),
            Collections.emptyList());

    /**
     * MPLS segment routing.
     */
    public static final ForwardingFunctionType MPLS_SEGMENT_ROUTING = new ForwardingFunctionType(
            Type.MPLS_SEGMENT_ROUTING,
            Sets.newHashSet(ETH_TYPE, MPLS_LABEL, MPLS_BOS),
            Lists.newArrayList(MATCH_ETH_TYPE_MPLS, MATCH_MPLS_BOS_TRUE),
            Collections.emptyList());

    /**
     * Pseudo-wire.
     */
    public static final ForwardingFunctionType PSEUDO_WIRE = new ForwardingFunctionType(
            Type.PSEUDO_WIRE,
            Sets.newHashSet(ETH_TYPE, MPLS_LABEL, MPLS_BOS),
            Lists.newArrayList(MATCH_ETH_TYPE_MPLS, MATCH_MPLS_BOS_FALSE),
            Collections.emptyList());

    /**
     * Unsupported type.
     */
    public static final ForwardingFunctionType UNKNOWN = new ForwardingFunctionType(
            Type.UNKNOWN,
            Collections.emptySet(),
            Collections.emptyList(),
            Collections.emptyList());

    private static final Set<ForwardingFunctionType> ALL_TYPES = Sets.newHashSet(
            L2_UNICAST,
            L2_BROADCAST,
            L2_BROADCAST_ALIAS,
            IPV4_ROUTING,
            IPV4_ROUTING_MULTICAST,
            IPV6_ROUTING,
            IPV6_ROUTING_MULTICAST,
            MPLS_SEGMENT_ROUTING,
            PSEUDO_WIRE,
            UNKNOWN
    );

    private static final Logger log = getLogger(ForwardingFunctionType.class);

    private final Type type;
    private final Set<Criterion.Type> expectedCriterionTypes;
    private final Map<Criterion.Type, List<Criterion>> matchCriteria;
    private final Map<Criterion.Type, List<Criterion>> mismatchCriteria;
    private final ForwardingFunctionType originalType;

    /**
     * Creates a new FFT.
     *
     * @param type                   the type
     * @param expectedCriterionTypes expected criterion types
     * @param matchCriteria          criterion instances to match
     * @param mismatchCriteria       criterion instance not to be matched
     */
    ForwardingFunctionType(Type type,
                           Set<Criterion.Type> expectedCriterionTypes,
                           Collection<Criterion> matchCriteria,
                           Collection<Criterion> mismatchCriteria) {
        this(type, expectedCriterionTypes, matchCriteria, mismatchCriteria, null);
    }

    /**
     * Creates a new alias FFT that if matched, should return the given original
     * FFT.
     *
     * @param type                   the type
     * @param expectedCriterionTypes expected criterion types
     * @param matchCriteria          criterion instances to match
     * @param mismatchCriteria       criterion instance not to be matched
     * @param original               original FFT to return
     */
    ForwardingFunctionType(Type type,
                           Set<Criterion.Type> expectedCriterionTypes,
                           Collection<Criterion> matchCriteria,
                           Collection<Criterion> mismatchCriteria,
                           ForwardingFunctionType original) {
        this.type = type;
        this.expectedCriterionTypes = ImmutableSet.copyOf(expectedCriterionTypes);
        this.matchCriteria = typeToCriteriaMap(matchCriteria);
        this.mismatchCriteria = typeToCriteriaMap(mismatchCriteria);
        this.originalType = original == null ? this : original;
    }

    /**
     * Gets all possible types.
     *
     * @return all possible types
     */
    private static Set<ForwardingFunctionType> values() {
        return ALL_TYPES;
    }

    /**
     * Gets type of forwarding function type.
     * @return the type of this forwarding function type
     */
    public Type type() {
        return type;
    }

    /**
     * Attempts to guess the forwarding function type of the given forwarding
     * objective.
     *
     * @param fwd the forwarding objective
     * @return forwarding function type. {@link #UNKNOWN} if the FFT cannot be
     * determined.
     */
    public static ForwardingFunctionType getForwardingFunctionType(ForwardingObjective fwd) {
        final Set<Criterion> criteria = criteriaIncludingMeta(fwd);
        final Set<Criterion.Type> criterionTypes = criteria.stream()
                .map(Criterion::type).collect(Collectors.toSet());

        final List<ForwardingFunctionType> candidates = ForwardingFunctionType.values().stream()
                // Keep FFTs which expected criterion types are the same found
                // in the fwd objective.
                .filter(fft -> fft.expectedCriterionTypes.equals(criterionTypes))
                // Keep FFTs which match criteria are found in the fwd objective.
                .filter(fft -> matchFft(criteria, fft))
                // Keep FFTs which mismatch criteria are NOT found in the objective.
                .filter(fft -> mismatchFft(criteria, fft))
                .collect(Collectors.toList());

        switch (candidates.size()) {
            case 1:
                return candidates.get(0).originalType;
            case 0:
                return UNKNOWN;
            default:
                log.warn("Multiple FFT candidates found: {} [{}]", candidates, fwd);
                return UNKNOWN;
        }
    }

    public static boolean matchFft(Collection<Criterion> criteria, ForwardingFunctionType fft) {
        return matchOrMismatchFft(criteria, fft.matchCriteria, false);
    }

    private static boolean mismatchFft(Collection<Criterion> criteria, ForwardingFunctionType fft) {
        return matchOrMismatchFft(criteria, fft.mismatchCriteria, true);
    }

    private static boolean matchOrMismatchFft(
            Collection<Criterion> criteria,
            Map<Criterion.Type, List<Criterion>> criteriaToMatch,
            boolean mismatch) {
        final Map<Criterion.Type, Criterion> givenCriteria = typeToCriterionMap(criteria);
        for (Criterion.Type typeToMatch : criteriaToMatch.keySet()) {
            if (!givenCriteria.containsKey(typeToMatch)) {
                return false;
            }
            final boolean matchFound = criteriaToMatch.get(typeToMatch).stream()
                    .anyMatch(c -> mismatch != givenCriteria.get(c.type()).equals(c));
            if (!matchFound) {
                return false;
            }
        }
        return true;
    }

    private static Set<Criterion> criteriaIncludingMeta(ForwardingObjective fwd) {
        final Set<Criterion> criteria = Sets.newHashSet();
        criteria.addAll(fwd.selector().criteria());
        // FIXME: Is this really needed? Meta is such an ambiguous field...
        if (fwd.meta() != null) {
            criteria.addAll(fwd.meta().criteria());
        }
        return criteria;
    }

    private static Map<Criterion.Type, List<Criterion>> typeToCriteriaMap(Collection<Criterion> criteria) {
        return criteria.stream().collect(Collectors.groupingBy(Criterion::type));
    }

    private static Map<Criterion.Type, Criterion> typeToCriterionMap(Collection<Criterion> criteria) {
        final ImmutableMap.Builder<Criterion.Type, Criterion> mapBuilder = ImmutableMap.builder();
        criteria.forEach(c -> mapBuilder.put(c.type(), c));
        return mapBuilder.build();
    }
}
