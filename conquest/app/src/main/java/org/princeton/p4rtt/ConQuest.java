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
package org.princeton.p4rtt;

import static org.onosproject.net.group.DefaultGroupBucket.createCloneGroupBucket;
import com.google.common.collect.ImmutableList;
import org.onlab.packet.Ip4Address;
import org.onlab.util.ImmutableByteSequence;
import org.onosproject.cfg.ComponentConfigService;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.group.GroupDescription;
import org.onosproject.net.group.GroupService;
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
import org.onosproject.net.pi.model.PiPipeconf;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiActionParam;
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
import org.onosproject.net.pi.model.PiTableId;

import org.onosproject.net.group.DefaultGroupDescription;
import org.onosproject.net.group.DefaultGroupKey;
import org.onosproject.net.group.GroupBuckets;

import static org.onosproject.net.pi.model.PiPipeconf.ExtensionType.CPU_PORT_TXT;

// Packet processor related imports.
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.ByteBuffer;
import org.onlab.packet.Ethernet;


import java.util.*;

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



    // Rtt Report data
    //public RttReport rttReport = new RttReport();

    // String ("srcIp,dstIp") : Int (avgRttValue)
    public Hashtable<String,Integer> flowAvgRttHashTable  = new Hashtable<>();

    // String ("srcIp,dstIp") : LinkedList
    public Hashtable<String, LinkedList<Integer>> flowLinkedListHashTable  = new Hashtable<>();



    private String getHexString(byte[] b) {
      String result = "";
      for (int i=0; i < b.length; i++) {
        result +=
              Integer.toString( ( b[i] & 0xff ) + 0x100, 16).substring( 1 );
      }
      return result;
    }


    private int getAverage(LinkedList<Integer> rttLinkedList) {
        int counter = 0;
        int total = 0;

        for (int i=0; i<rttLinkedList.size(); i++) {
            total += (int) rttLinkedList.get(i);
            counter++;
        }

        return (int) total/counter;
    }


    private class CustomPacketProcessor implements PacketProcessor {

        private final Logger log = LoggerFactory.getLogger(getClass());

        @Override
        public void process(PacketContext context){
            // Prints the unparsed packet in hex.
            Ethernet packet = context.inPacket().parsed();

            // If EtherType == 0x9001
            if (packet.getEtherType() == ConQuestPacket.TYPE_CONQ_REPORT) {

                ByteBuffer pktBuf = context.inPacket().unparsed();
                String strBuf = getHexString(pktBuf.array());
                //log.info("PARSED packet:");
                //log.info(strBuf);

                // RttPacket rttPacket;
                // For now, we manually parse...

                byte[] bstream = packet.getPayload().serialize();

                ByteBuffer bb = ByteBuffer.wrap(bstream);
                byte rttPacketType = bb.get();
                byte rttMatchedSuccess = bb.get();
                byte rttInsertedSuccess = bb.get();
                int rttVal = bb.getInt();
                //ipv4 hdr is 20 bytes = 5 int
                int IPv4hdr_1 = bb.getInt();
                int IPv4hdr_2 = bb.getInt();
                int IPv4hdr_3 = bb.getInt();
                int IPv4hdr_srcIP = bb.getInt();
                int IPv4hdr_dstIP = bb.getInt();
                int TCPhdr_srcPort = bb.getShort();
                if(TCPhdr_srcPort<0)TCPhdr_srcPort+=65536;
                int TCPhdr_dstPort = bb.getShort();
                if(TCPhdr_dstPort<0)TCPhdr_dstPort+=65536;


                // Logging
                //log.info("Parsed RTT shim header:");
                //log.info("RTT_Packet_Type: " + String.valueOf(rttPacketType));
                //log.info("RTT_Matched_Success: " + String.valueOf(rttMatchedSuccess));
                //log.info("RTT_Inserted_Success: " + String.valueOf(rttInsertedSuccess));
                //log.info("RTT_VAL prased: " + String.valueOf(rttVal));
                //log.info("RTT_VAL debug: " + String.valueOf(rttVal));

                //log.info("IP src: " + String.valueOf(Ip4Address.valueOf(IPv4hdr_srcIP)));
                //log.info("IP dst: " + String.valueOf(Ip4Address.valueOf(IPv4hdr_dstIP)));

                // Should be TCP. P4RTT does not calculate RTT with other protocols
                //if (ipv4Packet.getProtocol() == IPv4.PROTOCOL_TCP) {
                if (rttPacketType == 2 && rttMatchedSuccess == 1) {
                    // There is a report
                    // which means this is TCP, and RTT_val should now be nonzero.

                    log.info("IP src: " + String.valueOf(Ip4Address.valueOf(IPv4hdr_srcIP)));
                    log.info("IP dst: " + String.valueOf(Ip4Address.valueOf(IPv4hdr_dstIP)));
                    log.info("TCP src: " + String.valueOf(TCPhdr_srcPort));
                    log.info("TCP dst: " + String.valueOf(TCPhdr_dstPort));
                    log.info("RTT val: " + String.valueOf(rttVal));

                    ConQuestReport rttReport = new ConQuestReport();

                    // Populate Rtt Report data
                    rttReport.srcIpAddress = Ip4Address.valueOf(IPv4hdr_srcIP);
                    rttReport.dstIpAddress = Ip4Address.valueOf(IPv4hdr_dstIP);
                    rttReport.rttVal = rttVal;

                    // Update linkedlist
                    String key = String.join(",",rttReport.srcIpAddress.toString(),rttReport.dstIpAddress.toString());
                    LinkedList<Integer> rttLinkedList = flowLinkedListHashTable.get(key);
                    if (rttLinkedList==null) {
                        rttLinkedList = new LinkedList<>();
                    }
                    rttLinkedList.add(rttVal);
                    if (rttLinkedList.size() > MAX_QUEUE_LENGTH) {
                        rttLinkedList.removeFirst();
                    }
                    flowLinkedListHashTable.put(key, rttLinkedList);

                    // Recalculate avg and update.
                    int averageRtt = getAverage(rttLinkedList);
                    flowAvgRttHashTable.put(key,averageRtt);

                    log.info("Populated RttReport data");

                    int avg = getStatistics( rttReport.srcIpAddress , rttReport.dstIpAddress);
                    log.info("Average for flow: " + String.valueOf(avg/1e3) + "ms");

                    ArrayList<ConQuestReport> list = topNRttFlows(5,0);
                    log.info("Top 5 flows:{}",  Arrays.toString(list.toArray()));
                }
                else {
                    //log.info("No RTT report for this packet. Do nothing.");
                }


            }

            else {
                ByteBuffer pktBuf = context.inPacket().unparsed();
                String strBuf = getHexString(pktBuf.array());
                log.info("unparsed packet:");
                log.info(strBuf);
            }


            return;
        }
    }
    private CustomPacketProcessor processor = new CustomPacketProcessor();
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

    private DeviceId getP4rttDevice() {


        // FIXME: dummy method that just returns first available device
        for (Device device : deviceService.getAvailableDevices()) {
            return device.id();
        }
        log.error("No Devices found!");
        return null;
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
            var groupDescription =  new DefaultGroupDescription(
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
    public int getStatistics(Ip4Address srcAddr, Ip4Address dstAddr) {

        int result = -1;
        String key = String.join(",", srcAddr.toString(), dstAddr.toString());

        if (flowAvgRttHashTable.containsKey(key)) {
            result = (int) flowAvgRttHashTable.get(key);
        }

        return result;
    }

    @Override
    public ArrayList<ConQuestReport> topNRttFlows(int n, int threshold) {

        // Create list to return
        ArrayList<ConQuestReport> topRttReportList = new ArrayList<ConQuestReport>();

        // Convert flowAvgRttHashMap to List of entrySets and sort it by RTT value in descending order.
        ArrayList<Map.Entry<String, Integer>> flowsAvgRttList = new ArrayList<>(flowAvgRttHashTable.entrySet());
        Collections.sort(flowsAvgRttList, new Comparator<Map.Entry<String, Integer>>(){

            public int compare(Map.Entry<String, Integer> o1, Map.Entry<String, Integer> o2) {
                return o2.getValue().compareTo(o1.getValue());
            }
        });

        // Get Top N key-value pairs
        int numEntries = 0;
        for( Map.Entry<String, Integer> entry : flowsAvgRttList  ){

            // If N is not reached and entry's RTT value is over threshold, add.
            if ( (numEntries < n) && (entry.getValue() >= threshold) ) {

                // Key is string of: "srcIp,dstIp". So delimit by ",".
                String[] srcAndDst = entry.getKey().split(",");
                Ip4Address srcIpAddress = Ip4Address.valueOf(srcAndDst[0]);
                Ip4Address dstIpAddress = Ip4Address.valueOf(srcAndDst[1]);

                // Create Rtt report and add to return list. Increment # of entries.
                ConQuestReport rttReport = new ConQuestReport(srcIpAddress, dstIpAddress, entry.getValue());
                topRttReportList.add(rttReport);
                numEntries++;
            }

            // Else, we are done.
            else {
                break;
            }
        }

        return topRttReportList;
        //return (topRttReportList.isEmpty()) ? null : topRttReportList;
    }


    private FlowRule buildSetTypeEntry(DeviceId deviceId, int setTypeParam,
                                       Ip4Address src, int srcMask,
                                       Ip4Address dst, int dstMask) {
        PiCriterion match = PiCriterion.builder()
                .matchTernary(Constants.IPV4_SRC_KEY, src.toInt(), srcMask)
                .matchTernary(Constants.IPV4_DST_KEY, dst.toInt(), dstMask)
                .matchExact(Constants.IPV4_PROTO_KEY, IPV4_PROTO_TCP)
                .build();

        PiAction action = PiAction.builder()
                .withId(Constants.SET_TYPE_ACTION)
                .withParameter(
                        new PiActionParam(Constants.SET_TYPE_PARAM, setTypeParam))
                .build();

        return DefaultFlowRule.builder()
                .forDevice(deviceId).fromApp(appId).makePermanent()
                .forTable(Constants.MATCH_TYPE_TABLE)
                .withSelector(DefaultTrafficSelector.builder().matchPi(match).build())
                .withTreatment(DefaultTrafficTreatment.builder().piTableAction(action).build())
                .withPriority(DEFAULT_PRIORITY)
                .build();
    }

    @Override
    public void monitorFlowEverywhere(Ip4Address srcAddr, Ip4Address dstAddr) {
        for (Device device : deviceService.getAvailableDevices()) {
            monitorFlow(device.id(), srcAddr, dstAddr);
        }
    }

    @Override
    public void monitorFlow(DeviceId deviceId, Ip4Address srcAddr, Ip4Address dstAddr) {

        FlowRule seqEntry = buildSetTypeEntry(deviceId, Constants.P4RTT_TYPE_SEQ,
                srcAddr, ALL_ONES_32, dstAddr, ALL_ONES_32);
        FlowRule ackEntry = buildSetTypeEntry(deviceId, Constants.P4RTT_TYPE_ACK,
                dstAddr, ALL_ONES_32, srcAddr, ALL_ONES_32);

        flowRuleService.applyFlowRules(seqEntry, ackEntry);
        log.info("Added flow rules to monitor flow ({}, {}) on device {}", srcAddr, dstAddr, deviceId);
    }

    @Override
    public void removeSomeEntry(PiCriterion match, PiTableId tableId) {
        DeviceId deviceId = getP4rttDevice();
        FlowRule entry = DefaultFlowRule.builder()
                .forDevice(deviceId).fromApp(appId).makePermanent()
                .forTable(tableId)
                .withSelector(DefaultTrafficSelector.builder().matchPi(match).build())
                .withPriority(DEFAULT_PRIORITY)
                .build();

        /*
         *  FIXME: Stupid stupid slow hack, needed because removeFlowRules expects FlowRule objects
         *   with correct and complete actions and parameters, but P4Runtime deletion requests
         *   will not have those.
         */
        for (FlowEntry installedEntry : flowRuleService.getFlowEntriesById(appId)) {
            if (installedEntry.selector().equals(entry.selector())) {
                log.info("Found matching entry to remove.");
                flowRuleService.removeFlowRules(installedEntry);
                return;
            }
        }
        log.error("Did not find a flow rule with the given match conditions! Deleting nothing.");
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
