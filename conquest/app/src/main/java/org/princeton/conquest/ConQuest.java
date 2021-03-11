/*
 * Copyright 2020-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.princeton.conquest;

import com.google.common.collect.ImmutableList;
import org.onlab.packet.Ethernet;
import org.onlab.packet.Ip4Address;
import org.onlab.util.ImmutableByteSequence;
import org.onosproject.cfg.ComponentConfigService;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.Device;
import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowEntry;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.criteria.PiCriterion;
import org.onosproject.net.group.DefaultGroupDescription;
import org.onosproject.net.group.DefaultGroupKey;
import org.onosproject.net.group.GroupBuckets;
import org.onosproject.net.group.GroupDescription;
import org.onosproject.net.group.GroupService;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.pi.model.PiPipeconf;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.service.PiPipeconfService;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.ByteBuffer;
import java.util.Collection;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.LinkedList;
import java.util.Optional;
import java.util.Set;

import static org.onosproject.net.group.DefaultGroupBucket.createCloneGroupBucket;
import static org.onosproject.net.pi.model.PiPipeconf.ExtensionType.CPU_PORT_TXT;

/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true,
        service = {ConQuestService.class}
)
public class ConQuest implements ConQuestService {

    private final Logger log = LoggerFactory.getLogger(getClass());

    private ApplicationId appId;
    private static final int DEFAULT_PRIORITY = 10;
    private static final int MAX_QUEUE_LENGTH = 10;
    private static final int IPV4_PROTO_TCP = 6;
    private static final int ALL_ONES_32 = 0xffffffff;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ComponentConfigService cfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected DeviceService deviceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected GroupService groupService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PiPipeconfService piPipeconfService;

    // Begin packet processor code.
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    private Set<ConQuestReport> receivedReports = new HashSet<>();


    // Rtt Report data
    //public RttReport rttReport = new RttReport();

    // String ("srcIp,dstIp") : Int (avgRttValue)
    public Hashtable<String, Integer> flowAvgRttHashTable = new Hashtable<>();

    // String ("srcIp,dstIp") : LinkedList
    public Hashtable<String, LinkedList<Integer>> flowLinkedListHashTable = new Hashtable<>();


    private String getHexString(byte[] b) {
        String result = "";
        for (int i = 0; i < b.length; i++) {
            result +=
                    Integer.toString((b[i] & 0xff) + 0x100, 16).substring(1);
        }
        return result;
    }


    private int getAverage(LinkedList<Integer> rttLinkedList) {
        int counter = 0;
        int total = 0;

        for (int i = 0; i < rttLinkedList.size(); i++) {
            total += (int) rttLinkedList.get(i);
            counter++;
        }

        return (int) total / counter;
    }


    private class CustomPacketProcessor implements PacketProcessor {

        private final Logger log = LoggerFactory.getLogger(getClass());

        @Override
        public void process(PacketContext context) {
            // Prints the unparsed packet in hex.
            Ethernet packet = context.inPacket().parsed();

            if (packet.getEtherType() == Constants.CONQUEST_ETHERTYPE) {

                ByteBuffer pktBuf = context.inPacket().unparsed();
                String strBuf = getHexString(pktBuf.array());
                //log.info("PARSED packet:");
                //log.info(strBuf);

                // RttPacket rttPacket;
                // For now, we manually parse...

                byte[] bstream = packet.getPayload().serialize();

                ByteBuffer bb = ByteBuffer.wrap(bstream);

                Ip4Address srcIp = Ip4Address.valueOf(bb.getInt());
                Ip4Address dstIp = Ip4Address.valueOf(bb.getInt());
                short srcPort = bb.getShort();
                short dstPort = bb.getShort();
                byte protocol = bb.get();
                int queueSize = bb.getInt();

                ConQuestReport report = new ConQuestReport(srcIp, dstIp, srcPort, dstPort, protocol, queueSize);

                receivedReports.add(report);
                log.info("Received ConQuest report.");
            } else {
                log.debug("Received packet-in that wasn't for us. Do nothing.");
                ByteBuffer pktBuf = context.inPacket().unparsed();
                String strBuf = getHexString(pktBuf.array());
                log.debug("unparsed packet:");
                log.debug(strBuf);
            }
        }
    }

    private final CustomPacketProcessor processor = new CustomPacketProcessor();
    // End packet processor code.

    @Activate
    protected void activate() {
        // currently no properties to register
        //cfgService.registerProperties(getClass());
        appId = coreService.registerApplication(Constants.APP_NAME,
                () -> log.info("Periscope down."));


        // Register the packet processor.
        packetService.addProcessor(processor, PacketProcessor.director(1));

        // Set up clone sessions on all available devices
        addAllCloneSessions();

        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {
        // we didnt register anything
        //cfgService.unregisterProperties(getClass(), false);

        // Deregister the packet processor.
        packetService.removeProcessor(processor);
        // Remove clone sessions from all available devices
        removeAllCloneSessions();

        log.info("Stopped");
    }

    public Optional<Integer> getCpuPort(DeviceId deviceId) {
        Optional<PiPipeconf> optionalPiPipeconf = piPipeconfService.getPipeconf(deviceId);
        if (optionalPiPipeconf.isEmpty()) {
            return Optional.empty();
        }
        PiPipeconf pipeconf = optionalPiPipeconf.get();

        // The rest of this function is ripped straight from FabricCapabilities.java
        // We can't use it directly because it is ONOS-internal or whatever

        // This is probably brittle, but needed to dynamically get the CPU port
        // for different platforms.
        if (!pipeconf.extension(CPU_PORT_TXT).isPresent()) {
            log.warn("Missing {} extension in pipeconf {}", CPU_PORT_TXT, pipeconf.id());
            return Optional.empty();
        }
        try {
            final InputStream stream = pipeconf.extension(CPU_PORT_TXT).get();
            final BufferedReader buff = new BufferedReader(
                    new InputStreamReader(stream));
            final String str = buff.readLine();
            buff.close();
            if (str == null) {
                log.error("Empty CPU port file for {}", pipeconf.id());
                return Optional.empty();
            }
            try {
                return Optional.of(Integer.parseInt(str));
            } catch (NumberFormatException e) {
                log.error("Invalid CPU port for {}: {}", pipeconf.id(), str);
                return Optional.empty();
            }
        } catch (IOException e) {
            log.error("Unable to read CPU port file of {}: {}",
                    pipeconf.id(), e.getMessage());
            return Optional.empty();
        }
    }


    private void addCloneSessions(DeviceId deviceId) {
        // Mirroring sessions for report cloning.
        Set<Integer> cloneSessionIds = Constants.MIRROR_SESSION_IDS;
        final var optCpuPort = getCpuPort(deviceId);
        if (optCpuPort.isEmpty()) {
            log.warn("Cannot find CPU port for device {}, skipping adding clone sessions", deviceId);
            return;
        }
        final int cpuPort = optCpuPort.get();
        cloneSessionIds.stream()
                .map(sessionId -> {
                    final var buckets = ImmutableList.of(
                            createCloneGroupBucket(DefaultTrafficTreatment.builder()
                                    .setOutput(PortNumber.portNumber(cpuPort))
                                    .build()));
                    return new DefaultGroupDescription(
                            deviceId, GroupDescription.Type.CLONE,
                            new GroupBuckets(buckets),
                            new DefaultGroupKey(ImmutableByteSequence.copyFrom(sessionId).asArray()),
                            sessionId, appId);
                })
                .forEach(groupService::addGroup);
        log.info("Added clone sessions for device {}", deviceId);

    }


    private void addAllCloneSessions() {
        for (Device device : deviceService.getAvailableDevices()) {
            addCloneSessions(device.id());
        }
        /*
        for (Device device : deviceService.getAvailableDevices()) {
            log.info("Adding clone session {} to device {}", Constants.CONQUEST_CLONE_SESSION_ID, device.id());
            final GroupDescription cloneGroup = ConQuestUtils.buildCloneGroup(
                    appId,
                    device.id(),
                    Constants.CONQUEST_CLONE_SESSION_ID,
                    // Ports where to clone the packet.
                    // Just controller in this case.
                    Collections.singleton(PortNumber.CONTROLLER));
            groupService.addGroup(cloneGroup);
        }
         */
        log.info("Added all clone sessions.");
    }

    private void removeCloneSessions(DeviceId deviceId) {
        Set<Integer> cloneSessionIds = Constants.MIRROR_SESSION_IDS;
        final var optCpuPort = getCpuPort(deviceId);
        if (optCpuPort.isEmpty()) {
            log.warn("Cannot find CPU port for device {}, skipping removing clone sessions", deviceId);
            return;
        }
        final int cpuPort = optCpuPort.get();
        for (int sessionId : cloneSessionIds) {
            final var buckets = ImmutableList.of(
                    createCloneGroupBucket(DefaultTrafficTreatment.builder()
                            .setOutput(PortNumber.portNumber(cpuPort))
                            .build()));
            var groupDescription = new DefaultGroupDescription(
                    deviceId, GroupDescription.Type.CLONE,
                    new GroupBuckets(buckets),
                    new DefaultGroupKey(ImmutableByteSequence.copyFrom(sessionId).asArray()),
                    sessionId, appId);
            groupService.removeGroup(deviceId, groupDescription.appCookie(), appId);
        }
        log.info("Removing clone sessions for device {}", deviceId);
    }

    private void removeAllCloneSessions() {
        for (Device device : deviceService.getAvailableDevices()) {
            removeCloneSessions(device.id());
        }
    }

    @Override
    public void removeReportTriggers(DeviceId deviceId) {
        int count = 0;
        for (FlowEntry installedEntry : flowRuleService.getFlowEntriesById(appId)) {
            if (installedEntry.deviceId().equals(deviceId)
                    && installedEntry.table().equals(Constants.REPORT_TRIGGER_TABLE)) {
                flowRuleService.removeFlowRules(installedEntry);
                count++;
            }
        }
        log.info("Removed {} flow rules from device {}", count, deviceId);
    }

    @Override
    public void removeAllReportTriggers() {
        int count = 0;
        for (FlowEntry installedEntry : flowRuleService.getFlowEntriesById(appId)) {
            if (installedEntry.table().equals(Constants.REPORT_TRIGGER_TABLE)) {
                flowRuleService.removeFlowRules(installedEntry);
                count++;
            }
        }
        log.info("Removed {} flow rules from the network", count);

    }

    @Override
    public Collection<ConQuestReport> getReceivedReports() {
        return Set.copyOf(receivedReports);
    }

    @Override
    public void clearReceivedReports() {
        receivedReports.clear();
    }


    private Set<FlowRule> buildReportTriggerRules(DeviceId deviceId, int minQueueDelay, int minFlowSizeInQueue) {
        Set<FlowRule> rules = new HashSet<>();
        for (int ecnVal : new int[]{0, 1, 2, 3}) {
            PiCriterion match = PiCriterion.builder()
                    .matchRange(Constants.FLOW_SIZE_IN_QUEUE, minFlowSizeInQueue, Constants.FLOW_SIZE_RANGE_MAX)
                    .matchRange(Constants.QUEUE_DELAY, minQueueDelay, Constants.QUEUE_DELAY_RANGE_MAX)
                    .matchExact(Constants.ECN_BITS, ecnVal)
                    .build();

            PiAction action = PiAction.builder()
                    .withId(Constants.TRIGGER_REPORT)
                    .build();

            FlowRule rule = DefaultFlowRule.builder()
                    .forDevice(deviceId).fromApp(appId).makePermanent()
                    .forTable(Constants.REPORT_TRIGGER_TABLE)
                    .withSelector(DefaultTrafficSelector.builder().matchPi(match).build())
                    .withTreatment(DefaultTrafficTreatment.builder().piTableAction(action).build())
                    .withPriority(DEFAULT_PRIORITY)
                    .build();
            rules.add(rule);
        }
        return rules;
    }

    @Override
    public void addReportTrigger(DeviceId deviceId, int minQueueDelay, int minFlowSizeInQueue) {
        for (FlowRule rule : buildReportTriggerRules(deviceId, minQueueDelay, minFlowSizeInQueue)) {
            flowRuleService.applyFlowRules(rule);
        }
        log.info("Added report trigger flow rules for device {}", deviceId);
    }

    @Override
    public void addReportTriggerEverywhere(int minQueueDelay, int minFlowSizeInQueue) {
        for (Device device : deviceService.getAvailableDevices()) {
            addReportTrigger(device.id(), minQueueDelay, minFlowSizeInQueue);
        }
    }


    @Override
    public void removeAllEntries() {
        log.info("Clearing table entries installed by this app.");
        flowRuleService.removeFlowRulesById(appId);
    }


    @Modified
    public void modified(ComponentContext context) {
        log.info("Reconfigured");
    }

}
