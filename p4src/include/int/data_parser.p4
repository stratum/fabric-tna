// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0
#ifndef __INT_DATA_PARSER__
#define __INT_DATA_PARSER__

#include "define.p4"

parser IntDataParser(packet_in packet, inout parsed_headers_t hdr) {
    state start {
        transition select(hdr.intl4_shim.len_words) {
            INT_HEADER_LEN_WORDS: accept; // Header and tail only
            // Maximum 3 hops supports (8 metadata * 3)
            8w5: parse_int_data_1;
            8w6: parse_int_data_2;
            8w7: parse_int_data_3;
            8w8: parse_int_data_4;
            8w9: parse_int_data_5;
            8w10: parse_int_data_6;
            8w11: parse_int_data_7;
            8w12: parse_int_data_8;
            8w13: parse_int_data_9;
            8w14: parse_int_data_10;
            8w15: parse_int_data_11;
            8w16: parse_int_data_12;
            8w17: parse_int_data_13;
            8w18: parse_int_data_14;
            8w19: parse_int_data_15;
            8w20: parse_int_data_16;
            8w21: parse_int_data_17;
            8w22: parse_int_data_18;
            8w23: parse_int_data_19;
            8w24: parse_int_data_20;
            8w25: parse_int_data_21;
            8w26: parse_int_data_22;
            8w27: parse_int_data_23;
            8w28: parse_int_data_24;
            default: reject; // Oversized int data, TODO: mark error
        }
    }

    state parse_int_data_1 {
        packet.extract(hdr.int_data[0]);
        transition accept;
    }

    state parse_int_data_2 {
        packet.extract(hdr.int_data[0]);
        packet.extract(hdr.int_data[1]);
        transition accept;
    }

    state parse_int_data_3 {
        packet.extract(hdr.int_data[0]);
        packet.extract(hdr.int_data[1]);
        packet.extract(hdr.int_data[2]);
        transition accept;
    }

    state parse_int_data_4 {
        packet.extract(hdr.int_data[0]);
        packet.extract(hdr.int_data[1]);
        packet.extract(hdr.int_data[2]);
        packet.extract(hdr.int_data[3]);
        transition accept;
    }

    state parse_int_data_5 {
        packet.extract(hdr.int_data[0]);
        packet.extract(hdr.int_data[1]);
        packet.extract(hdr.int_data[2]);
        packet.extract(hdr.int_data[3]);
        packet.extract(hdr.int_data[4]);
        transition accept;
    }

    state parse_int_data_6 {
        packet.extract(hdr.int_data[0]);
        packet.extract(hdr.int_data[1]);
        packet.extract(hdr.int_data[2]);
        packet.extract(hdr.int_data[3]);
        packet.extract(hdr.int_data[4]);
        packet.extract(hdr.int_data[5]);
        transition accept;
    }

    state parse_int_data_7 {
        packet.extract(hdr.int_data[0]);
        packet.extract(hdr.int_data[1]);
        packet.extract(hdr.int_data[2]);
        packet.extract(hdr.int_data[3]);
        packet.extract(hdr.int_data[4]);
        packet.extract(hdr.int_data[5]);
        packet.extract(hdr.int_data[6]);
        transition accept;
    }

    state parse_int_data_8 {
        packet.extract(hdr.int_data[0]);
        packet.extract(hdr.int_data[1]);
        packet.extract(hdr.int_data[2]);
        packet.extract(hdr.int_data[3]);
        packet.extract(hdr.int_data[4]);
        packet.extract(hdr.int_data[5]);
        packet.extract(hdr.int_data[6]);
        packet.extract(hdr.int_data[7]);
        transition accept;
    }

    state parse_int_data_9 {
        packet.extract(hdr.int_data[0]);
        packet.extract(hdr.int_data[1]);
        packet.extract(hdr.int_data[2]);
        packet.extract(hdr.int_data[3]);
        packet.extract(hdr.int_data[4]);
        packet.extract(hdr.int_data[5]);
        packet.extract(hdr.int_data[6]);
        packet.extract(hdr.int_data[7]);
        packet.extract(hdr.int_data[8]);
        transition accept;
    }

    state parse_int_data_10 {
        packet.extract(hdr.int_data[0]);
        packet.extract(hdr.int_data[1]);
        packet.extract(hdr.int_data[2]);
        packet.extract(hdr.int_data[3]);
        packet.extract(hdr.int_data[4]);
        packet.extract(hdr.int_data[5]);
        packet.extract(hdr.int_data[6]);
        packet.extract(hdr.int_data[7]);
        packet.extract(hdr.int_data[8]);
        packet.extract(hdr.int_data[9]);
        transition accept;
    }

    state parse_int_data_11 {
        packet.extract(hdr.int_data[0]);
        packet.extract(hdr.int_data[1]);
        packet.extract(hdr.int_data[2]);
        packet.extract(hdr.int_data[3]);
        packet.extract(hdr.int_data[4]);
        packet.extract(hdr.int_data[5]);
        packet.extract(hdr.int_data[6]);
        packet.extract(hdr.int_data[7]);
        packet.extract(hdr.int_data[8]);
        packet.extract(hdr.int_data[9]);
        packet.extract(hdr.int_data[10]);
        transition accept;
    }

    state parse_int_data_12 {
        packet.extract(hdr.int_data[0]);
        packet.extract(hdr.int_data[1]);
        packet.extract(hdr.int_data[2]);
        packet.extract(hdr.int_data[3]);
        packet.extract(hdr.int_data[4]);
        packet.extract(hdr.int_data[5]);
        packet.extract(hdr.int_data[6]);
        packet.extract(hdr.int_data[7]);
        packet.extract(hdr.int_data[8]);
        packet.extract(hdr.int_data[9]);
        packet.extract(hdr.int_data[10]);
        packet.extract(hdr.int_data[11]);
        transition accept;
    }

    state parse_int_data_13 {
        packet.extract(hdr.int_data[0]);
        packet.extract(hdr.int_data[1]);
        packet.extract(hdr.int_data[2]);
        packet.extract(hdr.int_data[3]);
        packet.extract(hdr.int_data[4]);
        packet.extract(hdr.int_data[5]);
        packet.extract(hdr.int_data[6]);
        packet.extract(hdr.int_data[7]);
        packet.extract(hdr.int_data[8]);
        packet.extract(hdr.int_data[9]);
        packet.extract(hdr.int_data[10]);
        packet.extract(hdr.int_data[11]);
        packet.extract(hdr.int_data[12]);
        transition accept;
    }

    state parse_int_data_14 {
        packet.extract(hdr.int_data[0]);
        packet.extract(hdr.int_data[1]);
        packet.extract(hdr.int_data[2]);
        packet.extract(hdr.int_data[3]);
        packet.extract(hdr.int_data[4]);
        packet.extract(hdr.int_data[5]);
        packet.extract(hdr.int_data[6]);
        packet.extract(hdr.int_data[7]);
        packet.extract(hdr.int_data[8]);
        packet.extract(hdr.int_data[9]);
        packet.extract(hdr.int_data[10]);
        packet.extract(hdr.int_data[11]);
        packet.extract(hdr.int_data[12]);
        packet.extract(hdr.int_data[13]);
        transition accept;
    }

    state parse_int_data_15 {
        packet.extract(hdr.int_data[0]);
        packet.extract(hdr.int_data[1]);
        packet.extract(hdr.int_data[2]);
        packet.extract(hdr.int_data[3]);
        packet.extract(hdr.int_data[4]);
        packet.extract(hdr.int_data[5]);
        packet.extract(hdr.int_data[6]);
        packet.extract(hdr.int_data[7]);
        packet.extract(hdr.int_data[8]);
        packet.extract(hdr.int_data[9]);
        packet.extract(hdr.int_data[10]);
        packet.extract(hdr.int_data[11]);
        packet.extract(hdr.int_data[12]);
        packet.extract(hdr.int_data[13]);
        packet.extract(hdr.int_data[14]);
        transition accept;
    }

    state parse_int_data_16 {
        packet.extract(hdr.int_data[0]);
        packet.extract(hdr.int_data[1]);
        packet.extract(hdr.int_data[2]);
        packet.extract(hdr.int_data[3]);
        packet.extract(hdr.int_data[4]);
        packet.extract(hdr.int_data[5]);
        packet.extract(hdr.int_data[6]);
        packet.extract(hdr.int_data[7]);
        packet.extract(hdr.int_data[8]);
        packet.extract(hdr.int_data[9]);
        packet.extract(hdr.int_data[10]);
        packet.extract(hdr.int_data[11]);
        packet.extract(hdr.int_data[12]);
        packet.extract(hdr.int_data[13]);
        packet.extract(hdr.int_data[14]);
        packet.extract(hdr.int_data[15]);
        transition accept;
    }

    state parse_int_data_17 {
        packet.extract(hdr.int_data[0]);
        packet.extract(hdr.int_data[1]);
        packet.extract(hdr.int_data[2]);
        packet.extract(hdr.int_data[3]);
        packet.extract(hdr.int_data[4]);
        packet.extract(hdr.int_data[5]);
        packet.extract(hdr.int_data[6]);
        packet.extract(hdr.int_data[7]);
        packet.extract(hdr.int_data[8]);
        packet.extract(hdr.int_data[9]);
        packet.extract(hdr.int_data[10]);
        packet.extract(hdr.int_data[11]);
        packet.extract(hdr.int_data[12]);
        packet.extract(hdr.int_data[13]);
        packet.extract(hdr.int_data[14]);
        packet.extract(hdr.int_data[15]);
        packet.extract(hdr.int_data[16]);
        transition accept;
    }

    state parse_int_data_18 {
        packet.extract(hdr.int_data[0]);
        packet.extract(hdr.int_data[1]);
        packet.extract(hdr.int_data[2]);
        packet.extract(hdr.int_data[3]);
        packet.extract(hdr.int_data[4]);
        packet.extract(hdr.int_data[5]);
        packet.extract(hdr.int_data[6]);
        packet.extract(hdr.int_data[7]);
        packet.extract(hdr.int_data[8]);
        packet.extract(hdr.int_data[9]);
        packet.extract(hdr.int_data[10]);
        packet.extract(hdr.int_data[11]);
        packet.extract(hdr.int_data[12]);
        packet.extract(hdr.int_data[13]);
        packet.extract(hdr.int_data[14]);
        packet.extract(hdr.int_data[15]);
        packet.extract(hdr.int_data[16]);
        packet.extract(hdr.int_data[17]);
        transition accept;
    }

    state parse_int_data_19 {
        packet.extract(hdr.int_data[0]);
        packet.extract(hdr.int_data[1]);
        packet.extract(hdr.int_data[2]);
        packet.extract(hdr.int_data[3]);
        packet.extract(hdr.int_data[4]);
        packet.extract(hdr.int_data[5]);
        packet.extract(hdr.int_data[6]);
        packet.extract(hdr.int_data[7]);
        packet.extract(hdr.int_data[8]);
        packet.extract(hdr.int_data[9]);
        packet.extract(hdr.int_data[10]);
        packet.extract(hdr.int_data[11]);
        packet.extract(hdr.int_data[12]);
        packet.extract(hdr.int_data[13]);
        packet.extract(hdr.int_data[14]);
        packet.extract(hdr.int_data[15]);
        packet.extract(hdr.int_data[16]);
        packet.extract(hdr.int_data[17]);
        packet.extract(hdr.int_data[18]);
        transition accept;
    }

    state parse_int_data_20 {
        packet.extract(hdr.int_data[0]);
        packet.extract(hdr.int_data[1]);
        packet.extract(hdr.int_data[2]);
        packet.extract(hdr.int_data[3]);
        packet.extract(hdr.int_data[4]);
        packet.extract(hdr.int_data[5]);
        packet.extract(hdr.int_data[6]);
        packet.extract(hdr.int_data[7]);
        packet.extract(hdr.int_data[8]);
        packet.extract(hdr.int_data[9]);
        packet.extract(hdr.int_data[10]);
        packet.extract(hdr.int_data[11]);
        packet.extract(hdr.int_data[12]);
        packet.extract(hdr.int_data[13]);
        packet.extract(hdr.int_data[14]);
        packet.extract(hdr.int_data[15]);
        packet.extract(hdr.int_data[16]);
        packet.extract(hdr.int_data[17]);
        packet.extract(hdr.int_data[18]);
        packet.extract(hdr.int_data[19]);
        transition accept;
    }

    state parse_int_data_21 {
        packet.extract(hdr.int_data[0]);
        packet.extract(hdr.int_data[1]);
        packet.extract(hdr.int_data[2]);
        packet.extract(hdr.int_data[3]);
        packet.extract(hdr.int_data[4]);
        packet.extract(hdr.int_data[5]);
        packet.extract(hdr.int_data[6]);
        packet.extract(hdr.int_data[7]);
        packet.extract(hdr.int_data[8]);
        packet.extract(hdr.int_data[9]);
        packet.extract(hdr.int_data[10]);
        packet.extract(hdr.int_data[11]);
        packet.extract(hdr.int_data[12]);
        packet.extract(hdr.int_data[13]);
        packet.extract(hdr.int_data[14]);
        packet.extract(hdr.int_data[15]);
        packet.extract(hdr.int_data[16]);
        packet.extract(hdr.int_data[17]);
        packet.extract(hdr.int_data[18]);
        packet.extract(hdr.int_data[19]);
        packet.extract(hdr.int_data[20]);
        transition accept;
    }

    state parse_int_data_22 {
        packet.extract(hdr.int_data[0]);
        packet.extract(hdr.int_data[1]);
        packet.extract(hdr.int_data[2]);
        packet.extract(hdr.int_data[3]);
        packet.extract(hdr.int_data[4]);
        packet.extract(hdr.int_data[5]);
        packet.extract(hdr.int_data[6]);
        packet.extract(hdr.int_data[7]);
        packet.extract(hdr.int_data[8]);
        packet.extract(hdr.int_data[9]);
        packet.extract(hdr.int_data[10]);
        packet.extract(hdr.int_data[11]);
        packet.extract(hdr.int_data[12]);
        packet.extract(hdr.int_data[13]);
        packet.extract(hdr.int_data[14]);
        packet.extract(hdr.int_data[15]);
        packet.extract(hdr.int_data[16]);
        packet.extract(hdr.int_data[17]);
        packet.extract(hdr.int_data[18]);
        packet.extract(hdr.int_data[19]);
        packet.extract(hdr.int_data[20]);
        packet.extract(hdr.int_data[21]);
        transition accept;
    }

    state parse_int_data_23 {
        packet.extract(hdr.int_data[0]);
        packet.extract(hdr.int_data[1]);
        packet.extract(hdr.int_data[2]);
        packet.extract(hdr.int_data[3]);
        packet.extract(hdr.int_data[4]);
        packet.extract(hdr.int_data[5]);
        packet.extract(hdr.int_data[6]);
        packet.extract(hdr.int_data[7]);
        packet.extract(hdr.int_data[8]);
        packet.extract(hdr.int_data[9]);
        packet.extract(hdr.int_data[10]);
        packet.extract(hdr.int_data[11]);
        packet.extract(hdr.int_data[12]);
        packet.extract(hdr.int_data[13]);
        packet.extract(hdr.int_data[14]);
        packet.extract(hdr.int_data[15]);
        packet.extract(hdr.int_data[16]);
        packet.extract(hdr.int_data[17]);
        packet.extract(hdr.int_data[18]);
        packet.extract(hdr.int_data[19]);
        packet.extract(hdr.int_data[20]);
        packet.extract(hdr.int_data[21]);
        packet.extract(hdr.int_data[22]);
        transition accept;
    }

    state parse_int_data_24 {
        packet.extract(hdr.int_data[0]);
        packet.extract(hdr.int_data[1]);
        packet.extract(hdr.int_data[2]);
        packet.extract(hdr.int_data[3]);
        packet.extract(hdr.int_data[4]);
        packet.extract(hdr.int_data[5]);
        packet.extract(hdr.int_data[6]);
        packet.extract(hdr.int_data[7]);
        packet.extract(hdr.int_data[8]);
        packet.extract(hdr.int_data[9]);
        packet.extract(hdr.int_data[10]);
        packet.extract(hdr.int_data[11]);
        packet.extract(hdr.int_data[12]);
        packet.extract(hdr.int_data[13]);
        packet.extract(hdr.int_data[14]);
        packet.extract(hdr.int_data[15]);
        packet.extract(hdr.int_data[16]);
        packet.extract(hdr.int_data[17]);
        packet.extract(hdr.int_data[18]);
        packet.extract(hdr.int_data[19]);
        packet.extract(hdr.int_data[20]);
        packet.extract(hdr.int_data[21]);
        packet.extract(hdr.int_data[22]);
        packet.extract(hdr.int_data[23]);
        transition accept;
    }
}
#endif // __INT_DATA_PARSER__
