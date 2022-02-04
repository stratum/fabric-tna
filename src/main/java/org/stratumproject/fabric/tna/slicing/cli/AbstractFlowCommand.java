// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0
package org.stratumproject.fabric.tna.slicing.cli;

import org.apache.karaf.shell.api.action.Argument;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.onlab.packet.IPv4;
import org.onlab.packet.IpPrefix;
import org.onlab.packet.TpPort;
import org.onosproject.cli.AbstractShellCommand;
import org.onosproject.cli.net.IpProtocol;
import org.onosproject.cli.net.IpProtocolCompleter;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.TrafficSelector;

/**
 * Abstract CLI command to manipulate classifier flows.
 */
public abstract class AbstractFlowCommand extends AbstractShellCommand {
    @Argument(index = 0, name = "sliceId",
            description = "Slice ID",
            required = true)
    @Completion(SliceIdCompleter.class)
    int sliceId;

    @Argument(index = 1, name = "tc",
            description = "Traffic class",
            required = true)
    @Completion(TrafficClassCompleter.class)
    String tc;

    @Option(name = "-sip", aliases = "--srcIp",
            description = "Source IP prefix",
            valueToShowInHelp = "10.0.0.1/32")
    String srcIp;

    @Option(name = "-sp", aliases = "--srcPort",
            description = "Source L4 port",
            valueToShowInHelp = "1001")
    short srcPort;

    @Option(name = "-dip", aliases = "--dstIp",
            description = "Destination IP prefix",
            valueToShowInHelp = "10.0.0.2/32")
    String dstIp;

    @Option(name = "-dp", aliases = "--dstPort",
            description = "Destination L4 port",
            valueToShowInHelp = "1002")
    short dstPort;

    @Option(name = "-p", aliases = "--proto",
            description = "IP protocol",
            valueToShowInHelp = "0x11")
    @Completion(IpProtocolCompleter.class)
    String proto;

    protected TrafficSelector parseSelector() {
        TrafficSelector.Builder trafficSelectorBuilder = DefaultTrafficSelector.builder();
        if (srcIp != null) {
            trafficSelectorBuilder.matchIPSrc(IpPrefix.valueOf(srcIp));
        }
        if (dstIp != null) {
            trafficSelectorBuilder.matchIPDst(IpPrefix.valueOf(dstIp));
        }
        byte ipProtocol = 0;
        if (proto != null) {
            ipProtocol = (byte) (0xFF & IpProtocol.parseFromString(proto));
            trafficSelectorBuilder.matchIPProtocol(ipProtocol);
        }
        if (srcPort != 0) {
            if (ipProtocol == IPv4.PROTOCOL_TCP) {
                trafficSelectorBuilder.matchTcpSrc(TpPort.tpPort(srcPort));
            } else if (ipProtocol == IPv4.PROTOCOL_UDP) {
                trafficSelectorBuilder.matchUdpSrc(TpPort.tpPort(srcPort));
            } else {
                throw new IllegalArgumentException(
                        "Invalid or missing IP protocol, cannot parse L4 source port");
            }
        }
        if (dstPort != 0) {
            if (ipProtocol == IPv4.PROTOCOL_TCP) {
                trafficSelectorBuilder.matchTcpDst(TpPort.tpPort(dstPort));
            } else if (ipProtocol == IPv4.PROTOCOL_UDP) {
                trafficSelectorBuilder.matchUdpDst(TpPort.tpPort(dstPort));
            } else {
                throw new IllegalArgumentException(
                        "Invalid or missing IP protocol, cannot parse L4 destination port");
            }
        }
        return trafficSelectorBuilder.build();
    }
}
