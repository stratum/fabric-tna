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

import static com.google.common.base.Preconditions.checkArgument;

/**
 * Add flow from slice.
 */
@Service
@Command(scope = "fabric-tna", name = "classifier-flow-add", description = "Classify a flow")
public class FlowAddCommand extends AbstractShellCommand {
    @Argument(index = 0, name = "sliceId",
            description = "SliceId (0 - 15)",
            required = true, multiValued = false)
    int sliceId;

    @Argument(index = 1, name = "tc",
            description = "Traffic class. Used to classify the traffic." +
                " Possible values: BEST_EFFORT, CONTROL, REAL_TIME, ELASTIC",
            required = true, multiValued = false)
    String tc;

    @Option(name = "-sip", aliases = "--srcIp",
            description = "Source IP prefix",
            valueToShowInHelp = "10.0.0.1/32",
            multiValued = false)
    String srcIp;

    @Option(name = "-sp", aliases = "--srcPort",
            description = "Source L4 port",
            valueToShowInHelp = "1001",
            multiValued = false)
    short srcPort;

    @Option(name = "-dip", aliases = "--dstIp",
            description = "Destination IP prefix",
            valueToShowInHelp = "10.0.0.2/32",
            multiValued = false)
    String dstIp;

    @Option(name = "-dp", aliases = "--dstPort",
            description = "Destination L4 port",
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

        if (slicingService.addClassifierFlow(selector, SliceId.of(sliceId), TrafficClass.valueOf(tc))) {
            print("Flow %s added to slice %d tc %s", selector.toString(), sliceId, tc);
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
            checkArgument(ipProtocol == 0x06 || ipProtocol == 0x11, "Support TCP and UDP only");
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
