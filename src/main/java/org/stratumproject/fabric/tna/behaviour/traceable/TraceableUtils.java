// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package org.stratumproject.fabric.tna.behaviour.traceable;

import org.onlab.util.ImmutableByteSequence;
import org.onosproject.net.pi.model.PiMatchType;
import org.onosproject.net.pi.runtime.PiLpmFieldMatch;
import org.onosproject.net.pi.runtime.PiTableEntry;
import org.onosproject.net.pi.runtime.PiTernaryFieldMatch;

import java.util.Objects;

import static org.onlab.util.ImmutableByteSequence.copyFrom;

/**
 * Collection of utils for traceable package.
 */
final class TraceableUtils {

    private TraceableUtils() {
        // hides constructor.
    }

    /**
     * Select best table entry based on the prefix length.
     *
     * @param best current best entry
     * @param candidate candidate entry
     * @return the best entry
     */
    static PiTableEntry selectBestLpmEntry(PiTableEntry best, PiTableEntry candidate) {
        if (best == null) {
            return candidate;
        }
        // We should find the relative lpm match of the entries and then compare the prefix length
        PiLpmFieldMatch bestLpm = (PiLpmFieldMatch) best.matchKey().fieldMatches().stream()
                .filter(matches -> Objects.equals(matches.type(), PiMatchType.LPM))
                .findFirst()
                .orElse(null);
        PiLpmFieldMatch candidateLpm = (PiLpmFieldMatch) candidate.matchKey().fieldMatches().stream()
                .filter(matches -> Objects.equals(matches.type(), PiMatchType.LPM))
                .findFirst()
                .orElse(null);
        return bestLpm.prefixLength() > candidateLpm.prefixLength() ? best : candidate;
    }

    /**
     * Select best table entry based on the priority.
     *
     * @param best current best entry
     * @param candidate candidate entry
     * @return the best entry
     */
    static PiTableEntry selectBestTerEntry(PiTableEntry best, PiTableEntry candidate) {
        // Returns the best entry based on the priority field
        if (best == null || (best.priority().getAsInt() < candidate.priority().getAsInt())) {
            return candidate;
        }
        return best;
    }

    /**
     * Verify whether or not the provided input matches against the candidate.
     * It performs an lpm match.
     *
     * @param candidate the candidate
     * @param toBeMatched the provided input
     * @return true if the input matches against the candidate
     */
    static boolean lpmMatch(PiLpmFieldMatch candidate, PiLpmFieldMatch toBeMatched) {
        // Should not be null
        if (candidate == null || toBeMatched == null) {
            return false;
        }

        ImmutableByteSequence candidateValue = candidate.value();
        ImmutableByteSequence toBeMatchedValue = toBeMatched.value();

        // if the byte sequence are of different length - there is no match
        if (candidateValue.size() != toBeMatchedValue.size()) {
            return false;
        }

        // if the prefix length of the candidate is bigger - there is no match
        if (candidate.prefixLength() > toBeMatched.prefixLength()) {
            return false;
        }

        // if it is null or it is different - there was an error.
        return candidateValue.equals(maskedValue(toBeMatchedValue, candidate.prefixLength()));
    }

    /**
     * Verify whether or not the provided input matches against the candidate.
     * It performs a ternary match.
     *
     * @param candidate the candidate
     * @param toBeMatched the provided input
     * @return true if the input matches against the candidate
     */
    static boolean ternaryMatch(PiTernaryFieldMatch candidate, PiTernaryFieldMatch toBeMatched) {
        // Should not be null
        if (candidate == null || toBeMatched == null) {
            return false;
        }

        ImmutableByteSequence candidateValue = candidate.value();
        ImmutableByteSequence toBeMatchedValue = toBeMatched.value();
        ImmutableByteSequence candidateMask = candidate.mask();
        ImmutableByteSequence toBeMatchedMask = toBeMatched.mask();

        // if the values are of different length - there is no match
        if (candidateValue.size() != toBeMatchedValue.size()) {
            return false;
        }

        // if the masks are of different length - there is no match
        if (candidateMask.size() != toBeMatchedMask.size()) {
            return false;
        }

        // Let's build the masked value using the bytes array
        byte[] masked = new byte[candidateMask.size()];

        // Mask each byte
        for (int i = 0; i < masked.length; i++) {
            masked[i] = (byte) (toBeMatchedValue.asArray()[i] & candidateMask.asArray()[i]);
        }

        return candidateValue.equals(copyFrom(masked));
    }

    // Returns an immutable byte sequence representing the masked value. The masked value is built using
    // the prefix length of the candidate.
    private static ImmutableByteSequence maskedValue(ImmutableByteSequence toBeMasked, int prefixLength) {
        int addrByteLength = toBeMasked.size();
        int addrBitLength = addrByteLength * Byte.SIZE;

        // Verify the prefix length
        if ((prefixLength < 0) || (prefixLength > addrBitLength)) {
            return null;
        }

        // Number of bytes and extra bits that should be all 1s
        int maskBytes = prefixLength / Byte.SIZE;
        int maskBits = prefixLength % Byte.SIZE;
        byte[] mask = new byte[addrByteLength];

        // Set the bytes and extra bits to 1s
        for (int i = 0; i < maskBytes; i++) {
            mask[i] = (byte) 0xff;              // Set mask bytes to 1s
        }
        for (int i = maskBytes; i < addrByteLength; i++) {
            mask[i] = 0;                        // Set remaining bytes to 0s
        }
        // These are the extra bits that should be 1
        if (maskBits > 0) {
            mask[maskBytes] = (byte) (0xff << (Byte.SIZE - maskBits));
        }

        // Let's build the masked value using the bytes array
        byte[] masked = new byte[mask.length];

        // Mask each byte
        for (int i = 0; i < masked.length; i++) {
            masked[i] = (byte) (toBeMasked.asArray()[i] & mask[i]);
        }

        // Returns a new immutable sequence
        return copyFrom(masked);
    }
}
