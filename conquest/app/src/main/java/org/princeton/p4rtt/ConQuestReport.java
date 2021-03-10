package org.princeton.p4rtt;

import org.onlab.packet.Ip4Address;

public class ConQuestReport {

    Ip4Address srcIpAddress;
    Ip4Address dstIpAddress;
    int rttVal;

    /**
     * Constructs P4 RTT Report data
     *
     * @param
     */
    public ConQuestReport() {
        this.srcIpAddress = Ip4Address.ZERO;
        this.dstIpAddress = Ip4Address.ZERO;
        this.rttVal = -1;
    }

    /**
     * Constructs P4 RTT Report data with specific values
     * @param srcIpAddress Src IP address
     * @param dstIpAddress Dst IP address
     * @param rttVal Rtt value
     */
    public ConQuestReport(Ip4Address srcIpAddress, Ip4Address dstIpAddress, int rttVal) {
        this.srcIpAddress = srcIpAddress;
        this.dstIpAddress = dstIpAddress;
        this.rttVal = rttVal;
    }

    public String toString() {
        return String.format("%s->%s@%.2f(ms)", this.srcIpAddress.toString(),this.dstIpAddress.toString(),this.rttVal/1e3);
    }

    public String toVerboseString() {
        return String.format("%.2fms for flow (%s -> %s)", this.rttVal/1e3, this.srcIpAddress.toString(),this.dstIpAddress.toString());
    }
}
