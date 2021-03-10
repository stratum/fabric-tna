package org.princeton.p4rtt;

import org.onlab.packet.Ip4Address;

public class ConQuestReport {

    Ip4Address srcIpAddress;
    Ip4Address dstIpAddress;
    int rttVal;

    Ip4Address flowSrcIp;
    Ip4Address flowDstIp;
    protected short flowSrcPort;
    protected short flowDstPort;
    protected byte flowProtocol;
    protected int queueSize;

    /**
     * Constructs ConQuest Report data
     *
     */
    public ConQuestReport() {
        this.flowSrcIp = Ip4Address.ZERO;
        this.flowDstIp = Ip4Address.ZERO;
        this.queueSize = -1;
    }

    /**
     * Constructs ConQuest Report data with specific values
     * @param srcIpAddress Src IP address
     * @param dstIpAddress Dst IP address
     */
    public ConQuestReport(Ip4Address srcIpAddress, Ip4Address dstIpAddress,
                          short flowSrcPort, short flowDstPort,
                          byte flowProtocol, int queueSize) {
        this.srcIpAddress = srcIpAddress;
        this.dstIpAddress = dstIpAddress;
        this.flowSrcPort = flowSrcPort;
        this.flowDstPort = flowDstPort;
        this.flowProtocol = flowProtocol;
        this.queueSize = queueSize;
    }

    public String toString() {
        return String.format("%s->%s@%d", this.srcIpAddress.toString(),this.dstIpAddress.toString(),this.queueSize);
    }

    public String toVerboseString() {
        return String.format("%d for flow (%s -> %s)", queueSize,
                this.srcIpAddress.toString(),this.dstIpAddress.toString());
    }
}
