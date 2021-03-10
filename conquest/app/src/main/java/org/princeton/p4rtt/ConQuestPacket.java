package org.princeton.p4rtt;

import org.onlab.packet.BasePacket;

import java.nio.ByteBuffer;

public class ConQuestPacket extends BasePacket {

    public static final short TYPE_P4RTT = (short) 0x9001;

    protected byte RTT_packet_type;
    protected byte RTT_matched_success;
    protected byte RTT_inserted_success;
    protected int RTT_val;


    /**
     * Gets the Rtt Packet type.
     *
     * @return the RTT_packet_type as a byte
     */
    public byte getRTTPacketType() {
        return this.RTT_packet_type;
    }

    /**
     * Gets the Rtt matched success type.
     *
     * @return the RTT_matched_success as a byte
     */
    public byte getRTTMatchedSuccess() {
        return this.RTT_matched_success;
    }

    /**
     * Gets the Rtt inserted success.
     *
     * @return the RTT_inserted_success as a byte
     */
    public byte getRTTInsertedSuccess() {
        return this.RTT_inserted_success;
    }

    /**
     * Gets the Rtt value.
     *
     * @return the RTT_val as an int.
     */
    public int getRTTVal() {
        return this.RTT_val;
    }



    @Override
    public byte[] serialize() {

        byte[] payloadData = null;
        if (this.payload != null) {
            this.payload.setParent(this);
            payloadData = this.payload.serialize();
        }

        int length = 56;

        final byte[] data = new byte[length];
        final ByteBuffer bb = ByteBuffer.wrap(data);

        bb.put(this.RTT_packet_type);
        bb.put(this.RTT_matched_success);
        bb.put(this.RTT_inserted_success);
        bb.putInt(this.RTT_val);

        return data;

        /* Ethernet Serialize example.
        byte[] payloadData = null;
        if (this.payload != null) {
            this.payload.setParent(this);
            payloadData = this.payload.serialize();
        }

        int length = 14 + (this.vlanID == Ethernet.VLAN_UNTAGGED ? 0 : 4)
                + (this.qinqVID == Ethernet.VLAN_UNTAGGED ? 0 : 4)
                + (payloadData == null ? 0 : payloadData.length);
        if (this.pad && length < 60) {
            length = 60;
        }
        final byte[] data = new byte[length];
        final ByteBuffer bb = ByteBuffer.wrap(data);
        bb.put(this.destinationMACAddress.toBytes());
        bb.put(this.sourceMACAddress.toBytes());
        if (this.qinqVID != Ethernet.VLAN_UNTAGGED) {
            bb.putShort(this.qinqTPID);
            bb.putShort((short) (this.qInQPriorityCode << 13 | this.qinqVID & 0x0fff));
        }
        if (this.vlanID != Ethernet.VLAN_UNTAGGED) {
            bb.putShort(TYPE_VLAN);
            bb.putShort((short) (this.priorityCode << 13 | this.vlanID & 0x0fff));
        }
        bb.putShort(this.etherType);
        if (payloadData != null) {
            bb.put(payloadData);
        }
        if (this.pad) {
            Arrays.fill(data, bb.position(), data.length, (byte) 0x0);
        }
        return data;
        */
    }
}
