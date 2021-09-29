// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
package org.stratumproject.fabric.tna.slicing.cli;

import org.apache.karaf.shell.api.action.Argument;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.onlab.packet.IPv4;
import org.onlab.packet.IpPrefix;
import org.onlab.packet.TpPort;
import org.onosproject.cli.AbstractShellCommand;
import org.onosproject.cli.net.IpProtocol;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.TrafficSelector;
import org.stratumproject.fabric.tna.slicing.api.SliceId;
import org.stratumproject.fabric.tna.slicing.api.SlicingService;
import org.stratumproject.fabric.tna.slicing.api.TrafficClass;

/**
 * Remove flow from slice.
 */
@Service
@Command(scope = "fabric-tna", name = "classified-flow-remove", description = "Remove a classified flow")
public class FlowRemoveCommand extends AbstractShellCommand {
    @Argument(index = 0, name = "sliceId",
            description = "sliceId. Used to identify a slice.",
            required = true, multiValued = false)
    int sliceId;

    @Argument(index = 1, name = "tc",
            description = "Traffic class. Used to classify the traffic.",
            required = true, multiValued = false)
    String tc;

    @Option(name = "-sip", aliases = "--srcIp",
            description = "src IP",
            valueToShowInHelp = "10.0.0.1",
            multiValued = false)
    String srcIp;

    @Option(name = "-sp", aliases = "--srcPort",
            description = "src port",
            valueToShowInHelp = "1001",
            multiValued = false)
    short srcPort;

    @Option(name = "-dip", aliases = "--dstIp",
            description = "dst IP",
            valueToShowInHelp = "10.0.0.2",
            multiValued = false)
    String dstIp;

    @Option(name = "-dp", aliases = "--dstPort",
            description = "dst port",
            valueToShowInHelp = "1002",
            multiValued = false)
    short dstPort;

    @Option(name = "-p", aliases = "--proto",
            description = "IP protocol",
            valueToShowInHelp = "0x11",
            multiValued = false)
    String proto;

    @Override
    protected void doExecute() {
        SlicingService slicingService = getService(SlicingService.class);
        TrafficSelector selector = parseArguments();

        if (slicingService.removeFlow(selector, SliceId.of(sliceId), TrafficClass.valueOf(tc))) {
            print("Flow %s removed from slice %d tc %s", selector.toString(), sliceId, tc);
        } else {
            print("Failed to remove flow %s from slice %d tc %s", selector.toString(), sliceId, tc);
        }
    }

    private TrafficSelector parseArguments() {
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
            }
        }
        if (dstPort != 0) {
            if (ipProtocol == IPv4.PROTOCOL_TCP) {
                trafficSelectorBuilder.matchTcpDst(TpPort.tpPort(dstPort));
            } else if (ipProtocol == IPv4.PROTOCOL_UDP) {
                trafficSelectorBuilder.matchUdpDst(TpPort.tpPort(dstPort));
            }
        }
        return trafficSelectorBuilder.build();
    }
}
