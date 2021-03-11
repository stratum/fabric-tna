package org.princeton.conquest;

import org.onlab.packet.BasePacket;

import java.nio.ByteBuffer;

public class ConQuestPacket extends BasePacket {

    private static final int HEADER_SIZE = 32 + 32 + 16 + 16 + 8 + 32;


    protected int flowSrcIp;
    protected int flowDstIp;
    protected short flowSrcPort;
    protected short flowDstPort;
    protected byte flowProtocol;
    protected int queueSize;


    public int getFlowSrcIp() {
        return flowSrcIp;
    }

    public int getFlowDstIp() {
        return flowDstIp;
    }

    public short getFlowSrcPort() {
        return flowSrcPort;
    }

    public short getFlowDstPort() {
        return flowDstPort;
    }

    public byte getFlowProtocol() {
        return flowProtocol;
    }

    public int getQueueSize() {
        return queueSize;
    }


    @Override
    public byte[] serialize() {

        byte[] payloadData = null;
        if (this.payload != null) {
            this.payload.setParent(this);
            payloadData = this.payload.serialize();
        }

        int length = HEADER_SIZE + (payloadData == null ? 0 : payloadData.length);

        final byte[] data = new byte[HEADER_SIZE];
        final ByteBuffer bb = ByteBuffer.wrap(data);

        bb.putInt(this.flowSrcIp);
        bb.putInt(this.flowDstIp);
        bb.putShort(this.flowSrcPort);
        bb.putShort(this.flowDstPort);
        bb.put(this.flowProtocol);
        bb.putInt(this.queueSize);

        if (payloadData != null) {
            bb.put(payloadData);
        }

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
