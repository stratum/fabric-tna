package org.princeton.conquest;

import org.onlab.packet.Ip4Address;

public class ConQuestReport {

    Ip4Address srcIp;
    Ip4Address dstIp;
    protected short srcPort;
    protected short dstPort;
    protected byte protocol;
    protected int queueSize;

    /**
     * Constructs ConQuest Report data
     */
    public ConQuestReport() {
        this.srcIp = Ip4Address.ZERO;
        this.dstIp = Ip4Address.ZERO;
        this.srcPort = 0;
        this.dstPort = 0;
        this.protocol = 0;
        this.queueSize = -1;
    }

    /**
     * Constructs ConQuest Report data with specific values.
     *
     * @param srcIpAddress source IP address of the reported flow
     * @param dstIpAddress destination IP address of the reported flow
     * @param srcPort      source L4 port of the reported flow
     * @param dstPort      destination L4 port of the reported flow
     * @param protocol     L4 protocol of the reported flow
     * @param queueSize    queue occupancy of the reported flow
     */
    public ConQuestReport(Ip4Address srcIpAddress, Ip4Address dstIpAddress,
                          short srcPort, short dstPort,
                          byte protocol, int queueSize) {
        this.srcIp = srcIpAddress;
        this.dstIp = dstIpAddress;
        this.srcPort = srcPort;
        this.dstPort = dstPort;
        this.protocol = protocol;
        this.queueSize = queueSize;
    }

    public String toString() {
        String protocol;
        switch (this.protocol) {
            case 1:
                protocol = "ICMP";
                break;
            case 6:
                protocol = "TCP";
                break;
            case 17:
                protocol = "UDP";
                break;
            default:
                protocol = "UNKNOWN";
                break;
        }
        return String.format("(%s, %s:%d->%s:%d, %d)", protocol,
                this.srcIp.toString(), this.srcPort,
                this.dstIp.toString(), this.dstPort, this.queueSize);
    }
}
