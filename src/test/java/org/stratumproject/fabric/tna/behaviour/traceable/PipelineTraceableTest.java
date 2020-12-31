// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package org.stratumproject.fabric.tna.behaviour.traceable;

import com.google.common.collect.ImmutableSet;
import org.onlab.packet.EthType;
import org.onlab.packet.IpPrefix;
import org.onlab.packet.MacAddress;
import org.onlab.packet.MplsLabel;
import org.onlab.packet.VlanId;
import org.onosproject.TestApplicationId;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.GroupId;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;
import org.onosproject.net.behaviour.PipelineTraceable;
import org.onosproject.net.driver.Behaviour;
import org.onosproject.net.driver.DefaultDriverData;
import org.onosproject.net.driver.DefaultDriverHandler;
import org.onosproject.net.driver.DriverAdapter;
import org.onosproject.net.driver.DriverData;
import org.onosproject.net.driver.DriverHandler;
import org.onosproject.net.driver.HandlerBehaviour;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.pi.impl.PiFlowRuleTranslatorAdapter;
import org.onosproject.net.pi.impl.PiGroupTranslatorAdapter;
import org.onosproject.net.pi.impl.PiReplicationGroupTranslatorAdapter;
import org.onosproject.net.pi.model.PiPipelineInterpreter;
import org.onosproject.net.pi.service.PiFlowRuleTranslator;
import org.onosproject.net.pi.service.PiGroupTranslator;
import org.onosproject.net.pi.service.PiMeterTranslator;
import org.onosproject.net.pi.service.PiPipeconfService;
import org.onosproject.net.pi.service.PiReplicationGroupTranslator;
import org.onosproject.net.pi.service.PiTranslationService;
import org.stratumproject.fabric.tna.behaviour.FabricInterpreter;

import java.util.Set;

import static org.onlab.packet.EthType.EtherType.*;

/**
 * Overarching class for the traceable tests.
 */
public class PipelineTraceableTest {
    // Constants
    static final ApplicationId APP_ID = TestApplicationId.create("PipelineTraceableTest");
    static final int PRIORITY = 100;
    static final int ACL_PRIORITY_1 = 40000;
    static final int ACL_PRIORITY_2 = 30000;

    // Fabric constants
    static final byte[] ONE = {1};
    static final byte[] ZERO = {0};
    static final short EXACT_MATCH_ETH_TYPE = (short) 0xFFFF;

    // Device constants
    static final DeviceId DEVICE_ID = DeviceId.deviceId("foo");
    static final PortNumber DOWN_PORT = PortNumber.portNumber("1");
    static final ConnectPoint DOWN_CP = ConnectPoint.deviceConnectPoint(DEVICE_ID + "/" + DOWN_PORT.toLong());
    static final PortNumber UP_PORT_1 = PortNumber.portNumber("10");
    static final ConnectPoint UP_CP_1 = ConnectPoint.deviceConnectPoint(DEVICE_ID + "/" + UP_PORT_1.toLong());
    static final PortNumber UP_PORT_2 = PortNumber.portNumber("11");
    static final PortNumber MEMBER_1 = PortNumber.portNumber("2");
    static final PortNumber MEMBER_2 = PortNumber.portNumber("3");
    static final PortNumber DOWN_PORT_TAG = PortNumber.portNumber("4");
    static final ConnectPoint DOWN_CP_TAG = ConnectPoint.deviceConnectPoint(DEVICE_ID + "/" + DOWN_PORT_TAG.toLong());

    // IP constants
    static final IpPrefix PUNT_IPV4 = IpPrefix.valueOf("10.0.2.254/32");
    static final IpPrefix PUNT_IPV4_TAG = IpPrefix.valueOf("10.0.10.254/32");
    static final IpPrefix HOST_IPV4 = IpPrefix.valueOf("10.0.2.1/32");
    static final IpPrefix DEFAULT_IPV4 = IpPrefix.valueOf("0.0.0.0/0");
    static final IpPrefix SUBNET_IPV4 = IpPrefix.valueOf("10.0.3.0/24");

    // VLAN constants
    static final VlanId DEFAULT_VLAN = VlanId.vlanId((short) 4094);
    static final VlanId HOST_VLAN_1 = VlanId.vlanId((short) 100);
    static final VlanId HOST_VLAN_2 = VlanId.vlanId((short) 200);

    // MAC constants
    static final MacAddress LEAF_MAC = MacAddress.valueOf("00:00:00:00:02:04");
    static final MacAddress HOST_MAC = MacAddress.valueOf("00:00:00:00:00:01");
    static final MacAddress SPINE_MAC_1 = MacAddress.valueOf("00:00:00:00:02:26");
    static final MacAddress SPINE_MAC_2 = MacAddress.valueOf("00:00:00:00:02:27");
    static final MacAddress MISS_MAC = MacAddress.valueOf("00:00:00:00:06:66");

    // MPLS constants
    static final MplsLabel MPLS_LABEL = MplsLabel.mplsLabel(204);

    // Next constants
    static final int NEXT_BRIDGING = 1;
    static final int NEXT_ROUTING = 2;
    static final int NEXT_MPLS = 3;
    static final int NEXT_BROADCAST = 4;
    static final int NEXT_ECMP = 5;
    static final int NEXT_BROADCAST_2 = 6;

    // GroupId constants
    static final GroupId GROUP_ID_BRIDGING = GroupId.valueOf(NEXT_BRIDGING);
    static final GroupId GROUP_ID_ROUTING = GroupId.valueOf(NEXT_ROUTING);
    static final GroupId GROUP_ID_MPLS = GroupId.valueOf(NEXT_MPLS);
    static final GroupId GROUP_ID_BROADCAST = GroupId.valueOf(NEXT_BROADCAST);
    static final GroupId GROUP_ID_ECMP = GroupId.valueOf(NEXT_ECMP);
    static final GroupId GROUP_ID_BROADCAST_2 = GroupId.valueOf(NEXT_BROADCAST_2);

    // Group constants
    static final Set<PortNumber> BRODCAST_PORTS = ImmutableSet.of(DOWN_PORT, MEMBER_1, MEMBER_2);
    static final Set<PortNumber> BRODCAST_PORTS_2 = ImmutableSet.of(DOWN_PORT_TAG);

    // Tests objects
    protected TestDriver testDriver = new TestDriver();
    protected DefaultDriverData testDriverData = new DefaultDriverData(testDriver, DEVICE_ID);
    protected TestDriverHandler testDriverHandler = new TestDriverHandler(testDriverData);

    // Tests services
    protected PiPipeconfService pipeconfService;

    // Test cases
    enum TraceableTest {
        PUNT_IP_UNTAG,
        PUNT_IP_TAG,
        ARP_UNTAG,
        PUNT_LLDP,
        L2_BRIDG_UNTAG,
        L2_BRIDG_MISS,
        L2_BROAD_UNTAG,
        L3_UCAST_UNTAG,
        L3_ECMP,
        MPLS_ECMP,
    }

    // Input packets
    static final TrafficSelector IN_PUNT_IP_PACKET = DefaultTrafficSelector.builder()
            .matchInPort(DOWN_PORT)
            .matchEthType(IPV4.ethType().toShort())
            .matchVlanId(VlanId.NONE)
            .matchEthDst(LEAF_MAC)
            .matchIPDst(PUNT_IPV4)
            .build();
    static final TrafficSelector IN_PUNT_IP_PACKET_TAG = DefaultTrafficSelector.builder()
            .matchInPort(DOWN_PORT_TAG)
            .matchEthType(IPV4.ethType().toShort())
            .matchVlanId(HOST_VLAN_2)
            .matchEthDst(LEAF_MAC)
            .matchIPDst(PUNT_IPV4_TAG)
            .build();
    static final TrafficSelector IN_ARP_PACKET = DefaultTrafficSelector.builder()
            .matchInPort(DOWN_PORT)
            .matchEthType(EthType.EtherType.ARP.ethType().toShort())
            .matchVlanId(VlanId.NONE)
            .build();
    static final TrafficSelector IN_PUNT_LLDP_PACKET = DefaultTrafficSelector.builder()
            .matchInPort(UP_PORT_1)
            .matchEthType(EthType.EtherType.LLDP.ethType().toShort())
            .matchVlanId(VlanId.NONE)
            .build();
    static final TrafficSelector IN_L2_BRIDG_UNTAG_PACKET = DefaultTrafficSelector.builder()
            .matchInPort(DOWN_PORT)
            .matchEthType(IPV4.ethType().toShort())
            .matchVlanId(VlanId.NONE)
            .matchEthDst(HOST_MAC)
            .build();
    static final TrafficSelector IN_L2_BRIDG_MISS_PACKET = DefaultTrafficSelector.builder()
            .matchInPort(DOWN_PORT_TAG)
            .matchEthType(IPV4.ethType().toShort())
            .matchVlanId(HOST_VLAN_2)
            .matchEthDst(MISS_MAC)
            .build();
    static final TrafficSelector IN_L2_BROAD_UNTAG_PACKET = DefaultTrafficSelector.builder()
            .matchInPort(DOWN_PORT)
            .matchVlanId(VlanId.NONE)
            .build();
    static final TrafficSelector IN_L3_UCAST_UNTAG_PACKET = DefaultTrafficSelector.builder()
            .matchInPort(UP_PORT_1)
            .matchEthDst(LEAF_MAC)
            .matchEthType(IPV4.ethType().toShort())
            .matchVlanId(VlanId.NONE)
            .matchIPDst(HOST_IPV4)
            .build();
    static final TrafficSelector IN_MPLS_ECMP_PACKET = DefaultTrafficSelector.builder()
            .matchInPort(UP_PORT_1)
            .matchEthDst(LEAF_MAC)
            .matchEthType(MPLS_UNICAST.ethType().toShort())
            .matchVlanId(VlanId.NONE)
            .matchMplsLabel(MPLS_LABEL)
            .matchMplsBos(true)
            .matchMetadata(IPV4.ethType().toShort())
            .build();
    static final TrafficSelector IN_L3_ECMP_PACKET = DefaultTrafficSelector.builder()
            .matchInPort(DOWN_PORT)
            .matchEthDst(LEAF_MAC)
            .matchEthType(IPV4.ethType().toShort())
            .matchVlanId(VlanId.NONE)
            .matchIPDst(SUBNET_IPV4)
            .build();

    // Output packet
    static final TrafficSelector OUT_L3_UCAST_UNTAG_PACKET = DefaultTrafficSelector.builder()
            .matchInPort(UP_PORT_1)
            .matchEthSrc(LEAF_MAC)
            .matchEthDst(HOST_MAC)
            .matchEthType(IPV4.ethType().toShort())
            .matchVlanId(VlanId.NONE)
            .matchIPDst(HOST_IPV4)
            .build();
    static final TrafficSelector OUT_MPLS_ECMP_PACKET = DefaultTrafficSelector.builder()
            .matchInPort(UP_PORT_1)
            .matchEthSrc(LEAF_MAC)
            .matchEthDst(SPINE_MAC_1)
            .matchEthType(IPV4.ethType().toShort())
            .matchVlanId(VlanId.NONE)
            .build();
    static final TrafficSelector OUT_L3_ECMP_PACKET_1 = DefaultTrafficSelector.builder()
            .matchInPort(DOWN_PORT)
            .matchEthSrc(LEAF_MAC)
            .matchEthDst(SPINE_MAC_1)
            .matchEthType(MPLS_UNICAST.ethType().toShort())
            .matchMplsLabel(MPLS_LABEL)
            .matchMplsBos(true)
            .matchVlanId(VlanId.NONE)
            .matchIPDst(SUBNET_IPV4)
            .matchMetadata(IPV4.ethType().toShort())
            .build();
    static final TrafficSelector OUT_L3_ECMP_PACKET_2 = DefaultTrafficSelector.builder()
            .matchInPort(DOWN_PORT)
            .matchEthSrc(LEAF_MAC)
            .matchEthDst(SPINE_MAC_2)
            .matchEthType(MPLS_UNICAST.ethType().toShort())
            .matchMplsLabel(MPLS_LABEL)
            .matchMplsBos(true)
            .matchVlanId(VlanId.NONE)
            .matchIPDst(SUBNET_IPV4)
            .matchMetadata(IPV4.ethType().toShort())
            .build();

    // Expected meta
    static final FabricTraceableMetadata PUNT_IP_METADATA = FabricTraceableMetadata.builder()
            .setIPv4FwdType()
            .setSkipNext()
            .setVlanId(HOST_VLAN_1.toShort())
            .setNextId(-1)
            .setPuntToController()
            .build();
    static final FabricTraceableMetadata PUNT_IP_METADATA_TAG = FabricTraceableMetadata.builder()
            .setIPv4FwdType()
            .setSkipNext()
            .setVlanId(HOST_VLAN_2.toShort())
            .setNextId(-1)
            .setPuntToController()
            .build();
    static final FabricTraceableMetadata ARP_METADATA = FabricTraceableMetadata.builder()
            .setBridgingFwdType()
            .setVlanId(HOST_VLAN_1.toShort())
            .setNextId(NEXT_BROADCAST)
            .setCopyToController()
            .setGroupId(GROUP_ID_BROADCAST.id())
            .setIsMulticast()
            .build();
    static final FabricTraceableMetadata ARP_METADATA_1 = FabricTraceableMetadata.builder()
            .setBridgingFwdType()
            .setVlanId(VlanId.NONE.toShort())
            .setNextId(NEXT_BROADCAST)
            .setCopyToController()
            .setGroupId(GROUP_ID_BROADCAST.id())
            .setIsMulticast()
            .setOutPort(MEMBER_1)
            .build();
    static final FabricTraceableMetadata ARP_METADATA_2 = FabricTraceableMetadata.builder()
            .setBridgingFwdType()
            .setVlanId(VlanId.NONE.toShort())
            .setNextId(NEXT_BROADCAST)
            .setCopyToController()
            .setGroupId(GROUP_ID_BROADCAST.id())
            .setIsMulticast()
            .setOutPort(MEMBER_2)
            .build();
    static final FabricTraceableMetadata PUNT_LLDP_METADATA = FabricTraceableMetadata.builder()
            .setBridgingFwdType()
            .setSkipNext()
            .setVlanId(DEFAULT_VLAN.toShort())
            .setNextId(-1)
            .setPuntToController()
            .build();
    static final FabricTraceableMetadata L2_BRIDG_UNTAG_METADATA = FabricTraceableMetadata.builder()
            .setBridgingFwdType()
            .setVlanId(VlanId.NONE.toShort())
            .setNextId(NEXT_BRIDGING)
            .setGroupId(GROUP_ID_BRIDGING.id())
            .setOutPort(MEMBER_1)
            .build();
    static final FabricTraceableMetadata L2_BRIDG_MISS_METADATA = FabricTraceableMetadata.builder()
            .setBridgingFwdType()
            .setVlanId(HOST_VLAN_2.toShort())
            .setNextId(NEXT_BROADCAST_2)
            .setGroupId(GROUP_ID_BROADCAST_2.id())
            .setIsMulticast()
            .build();
    static final FabricTraceableMetadata L2_BROAD_UNTAG_METADATA = FabricTraceableMetadata.builder()
            .setBridgingFwdType()
            .setVlanId(HOST_VLAN_1.toShort())
            .setNextId(NEXT_BROADCAST)
            .setGroupId(GROUP_ID_BROADCAST.id())
            .setIsMulticast()
            .build();
    static final FabricTraceableMetadata L2_BROAD_UNTAG_METADATA_1 = FabricTraceableMetadata.builder()
            .setBridgingFwdType()
            .setVlanId(VlanId.NONE.toShort())
            .setNextId(NEXT_BROADCAST)
            .setGroupId(GROUP_ID_BROADCAST.id())
            .setIsMulticast()
            .setOutPort(MEMBER_1)
            .build();
    static final FabricTraceableMetadata L2_BROAD_UNTAG_METADATA_2 = FabricTraceableMetadata.builder()
            .setBridgingFwdType()
            .setVlanId(VlanId.NONE.toShort())
            .setNextId(NEXT_BROADCAST)
            .setGroupId(GROUP_ID_BROADCAST.id())
            .setIsMulticast()
            .setOutPort(MEMBER_2)
            .build();
    static final FabricTraceableMetadata L3_UCAST_UNTAG_METADATA = FabricTraceableMetadata.builder()
            .setIPv4FwdType()
            .setVlanId(VlanId.NONE.toShort())
            .setNextId(NEXT_ROUTING)
            .setGroupId(GROUP_ID_ROUTING.id())
            .setOutPort(DOWN_PORT)
            .build();
    static final FabricTraceableMetadata MPLS_ECMP_METADATA = FabricTraceableMetadata.builder()
            .setMplsFwdType()
            .setVlanId(VlanId.NONE.toShort())
            .setNextId(NEXT_MPLS)
            .setMplsLabel(0)
            .setGroupId(GROUP_ID_MPLS.id())
            .setOutPort(UP_PORT_2)
            .build();
    static final FabricTraceableMetadata L3_ECMP_METADATA_1 = FabricTraceableMetadata.builder()
            .setIPv4FwdType()
            .setVlanId(VlanId.NONE.toShort())
            .setNextId(NEXT_ECMP)
            .setMplsLabel(MPLS_LABEL.toInt())
            .setGroupId(GROUP_ID_ECMP.id())
            .setOutPort(UP_PORT_1)
            .build();
    static final FabricTraceableMetadata L3_ECMP_METADATA_2 = FabricTraceableMetadata.builder()
            .setIPv4FwdType()
            .setVlanId(VlanId.NONE.toShort())
            .setNextId(NEXT_ECMP)
            .setMplsLabel(MPLS_LABEL.toInt())
            .setGroupId(GROUP_ID_ECMP.id())
            .setOutPort(UP_PORT_2)
            .build();

    // Test class for driver handler
    class TestDriverHandler extends DefaultDriverHandler {

        public TestDriverHandler(DriverData driverData) {
            super(driverData);
        }

        @Override
        @SuppressWarnings("unchecked")
        public <T> T get(Class<T> serviceClass) {
            if (serviceClass.equals(PiPipeconfService.class)) {
                return (T) pipeconfService;
            } else if (serviceClass.equals(PiTranslationService.class)) {
                return (T) new TestPiTranslationService();
            }
            return null;
        }
    }

    // Test class for driver
    private static class TestDriver extends DriverAdapter {

        @Override
        public boolean hasBehaviour(Class<? extends Behaviour> behaviourClass) {
            if (behaviourClass == PipelineTraceable.class) {
                return true;
            } else if (behaviourClass == PiPipelineInterpreter.class) {
                return true;
            }
            return false;
        }

        @Override
        @SuppressWarnings("unchecked")
        public <T extends Behaviour> T createBehaviour(DriverHandler handler, Class<T> behaviourClass) {
            T behaviour = null;
            if (behaviourClass == PipelineTraceable.class) {
                behaviour = (T) new FabricTnaPipelineTraceable();
            } else if (behaviourClass == PiPipelineInterpreter.class) {
                behaviour = (T) new FabricInterpreter();
            } else {
                return null;
            }
            behaviour.setData(handler.data());
            ((HandlerBehaviour) behaviour).setHandler(handler);
            return behaviour;
        }

    }

    private class TestPiTranslationService implements PiTranslationService {

        private PiFlowRuleTranslator piFlowRuleTranslator = new PiFlowRuleTranslatorAdapter();
        private PiReplicationGroupTranslator piReplicationGroupTranslator = new PiReplicationGroupTranslatorAdapter();
        private PiGroupTranslator piGroupTranslator = new PiGroupTranslatorAdapter();

        @Override
        public PiFlowRuleTranslator flowRuleTranslator() {
            return piFlowRuleTranslator;
        }

        @Override
        public PiGroupTranslator groupTranslator() {
            return piGroupTranslator;
        }

        @Override
        public PiMeterTranslator meterTranslator() {
            return null;
        }

        @Override
        public PiReplicationGroupTranslator replicationGroupTranslator() {
            return piReplicationGroupTranslator;
        }
    }

}
