# SPDX-FileCopyrightText: Copyright 2020-present Open Networking Foundation.
# SPDX-License-Identifier: Apache-2.0

import struct

from scapy.fields import BitField, ByteField, IntField, ShortField
from scapy.layers.inet import IP, UDP
from scapy.packet import Packet, bind_layers

UDP_GTP_PORT = 2152


class GTPU(Packet):
    name = "GTP-U Header"
    fields_desc = [
        BitField("version", 1, 3),
        BitField("PT", 1, 1),
        BitField("reserved", 0, 1),
        BitField("E", 0, 1),
        BitField("S", 0, 1),
        BitField("PN", 0, 1),
        ByteField("gtp_type", 255),
        ShortField("length", None),
        IntField("teid", 0),
    ]

    def post_build(self, pkt, payload):
        pkt += payload
        # Set the length field if it is unset
        if self.length is None:
            length = len(pkt) - 8
            pkt = pkt[:2] + struct.pack("!H", length) + pkt[4:]
        return pkt


# Register our GTPU header with scapy for dissection
bind_layers(UDP, GTPU, dport=UDP_GTP_PORT)
bind_layers(GTPU, IP)
