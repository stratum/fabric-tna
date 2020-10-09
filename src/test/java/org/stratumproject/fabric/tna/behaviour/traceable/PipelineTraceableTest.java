// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0

package org.stratumproject.fabric.tna.behaviour.traceable;

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
import org.onosproject.net.pi.impl.PiFlowRuleTranslatorImpl;
import org.onosproject.net.pi.model.PiPipelineInterpreter;
import org.onosproject.net.pi.service.PiFlowRuleTranslator;
import org.onosproject.net.pi.service.PiGroupTranslator;
import org.onosproject.net.pi.service.PiMeterTranslator;
import org.onosproject.net.pi.service.PiPipeconfService;
import org.onosproject.net.pi.service.PiReplicationGroupTranslator;
import org.onosproject.net.pi.service.PiTranslationService;
import org.stratumproject.fabric.tna.behaviour.FabricInterpreter;

import static org.onlab.packet.EthType.EtherType.IPV4;
import static org.onlab.packet.EthType.EtherType.MPLS_UNICAST;

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
    static final PortNumber UP_PORT = PortNumber.portNumber("10");
    static final ConnectPoint UP_CP = ConnectPoint.deviceConnectPoint(DEVICE_ID + "/" + UP_PORT.toLong());

    // IP constants
    static final IpPrefix PUNT_IPV4 = IpPrefix.valueOf("10.0.2.254/32");
    static final IpPrefix HOST_IPV4 = IpPrefix.valueOf("10.0.2.1/32");
    static final IpPrefix DEFAULT_IPV4 = IpPrefix.valueOf("0.0.0.0/0");
    static final IpPrefix SUBNET_IPV4 = IpPrefix.valueOf("10.0.3.0/24");

    // VLAN constants
    static final VlanId HOST_VLAN = VlanId.vlanId((short) 100);
    static final VlanId DEFAULT_VLAN = VlanId.vlanId((short) 4094);

    // MAC constants
    static final MacAddress LEAF_MAC = MacAddress.valueOf("00:00:00:00:02:04");
    static final MacAddress HOST_MAC = MacAddress.valueOf("00:00:00:00:00:01");

    // MPLS constants
    static final MplsLabel MPLS_LABEL = MplsLabel.mplsLabel(203);

    // Next constants
    static final int NEXT_BRIDGING = 1;
    static final int NEXT_ROUTING = 2;
    static final int NEXT_MPLS = 3;
    static final int NEXT_BROADCAST = 4;
    static final int NEXT_ECMP = 5;

    // GroupId constants
    static final GroupId GROUP_ID_BRIDGING = GroupId.valueOf(NEXT_BRIDGING);
    static final GroupId GROUP_ID_ROUTING = GroupId.valueOf(NEXT_ROUTING);
    static final GroupId GROUP_ID_MPLS = GroupId.valueOf(NEXT_MPLS);
    static final GroupId GROUP_ID_BROADCAST = GroupId.valueOf(NEXT_BROADCAST);
    static final GroupId GROUP_ID_ECMP = GroupId.valueOf(NEXT_ECMP);

    // Tests objects
    protected TestDriver testDriver = new TestDriver();
    protected DefaultDriverData testDriverData = new DefaultDriverData(testDriver, DEVICE_ID);
    protected TestDriverHandler testDriverHandler = new TestDriverHandler(testDriverData);

    // Tests services
    protected PiPipeconfService pipeconfService;

    // Test cases
    enum TraceableTest {
        PUNT_IP,
        ARP_UNTAG,
        PUNT_LLDP,
        L2_BRIDG_UNTAG,
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
    static final TrafficSelector IN_ARP_PACKET = DefaultTrafficSelector.builder()
            .matchInPort(DOWN_PORT)
            .matchEthType(EthType.EtherType.ARP.ethType().toShort())
            .matchVlanId(VlanId.NONE)
            .build();
    static final TrafficSelector IN_PUNT_LLDP_PACKET = DefaultTrafficSelector.builder()
            .matchInPort(UP_PORT)
            .matchEthType(EthType.EtherType.LLDP.ethType().toShort())
            .matchVlanId(VlanId.NONE)
            .build();
    static final TrafficSelector IN_L2_BRIDG_UNTAG_PACKET = DefaultTrafficSelector.builder()
            .matchInPort(DOWN_PORT)
            .matchEthType(IPV4.ethType().toShort())
            .matchVlanId(VlanId.NONE)
            .matchEthDst(HOST_MAC)
            .build();
    static final TrafficSelector IN_L2_BROAD_UNTAG_PACKET = DefaultTrafficSelector.builder()
            .matchInPort(DOWN_PORT)
            .matchVlanId(VlanId.NONE)
            .build();
    static final TrafficSelector IN_L3_UCAST_UNTAG_PACKET = DefaultTrafficSelector.builder()
            .matchInPort(UP_PORT)
            .matchEthDst(LEAF_MAC)
            .matchEthType(IPV4.ethType().toShort())
            .matchVlanId(VlanId.NONE)
            .matchIPDst(HOST_IPV4)
            .build();
    static final TrafficSelector IN_MPLS_ECMP_PACKET = DefaultTrafficSelector.builder()
            .matchInPort(UP_PORT)
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

    // Expected meta
    static final FabricTraceableMetadata PUNT_IP_METADATA = FabricTraceableMetadata.builder()
            .setIPv4FwdType()
            .setSkipNext()
            .setVlanId(HOST_VLAN.toShort())
            .setNextId(-1)
            .setPuntToController()
            .build();
    static final FabricTraceableMetadata ARP_METADATA = FabricTraceableMetadata.builder()
            .setBridgingFwdType()
            .setVlanId(HOST_VLAN.toShort())
            .setNextId(NEXT_BROADCAST)
            .setCopyToController()
            .setGroupId(GROUP_ID_BROADCAST.id())
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
            .setVlanId(HOST_VLAN.toShort())
            .setNextId(NEXT_BRIDGING)
            .setGroupId(GROUP_ID_BRIDGING.id())
            .build();
    static final FabricTraceableMetadata L2_BROAD_UNTAG_METADATA = FabricTraceableMetadata.builder()
            .setBridgingFwdType()
            .setVlanId(HOST_VLAN.toShort())
            .setNextId(NEXT_BROADCAST)
            .setGroupId(GROUP_ID_BROADCAST.id())
            .build();
    static final FabricTraceableMetadata L3_UCAST_UNTAG_METADATA = FabricTraceableMetadata.builder()
            .setIPv4FwdType()
            .setVlanId(DEFAULT_VLAN.toShort())
            .setNextId(NEXT_ROUTING)
            .setGroupId(GROUP_ID_ROUTING.id())
            .build();
    static final FabricTraceableMetadata MPLS_ECMP_METADATA = FabricTraceableMetadata.builder()
            .setMplsFwdType()
            .setVlanId(DEFAULT_VLAN.toShort())
            .setNextId(NEXT_MPLS)
            .setMplsLabel(0)
            .setGroupId(GROUP_ID_MPLS.id())
            .build();
    static final FabricTraceableMetadata L3_ECMP_METADATA = FabricTraceableMetadata.builder()
            .setIPv4FwdType()
            .setVlanId(HOST_VLAN.toShort())
            .setNextId(NEXT_ECMP)
            .setMplsLabel(0)
            .setGroupId(GROUP_ID_ECMP.id())
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

        @Override
        public PiFlowRuleTranslator flowRuleTranslator() {
            return PiFlowRuleTranslatorImpl.getInstance();
        }

        @Override
        public PiGroupTranslator groupTranslator() {
            return null;
        }

        @Override
        public PiMeterTranslator meterTranslator() {
            return null;
        }

        @Override
        public PiReplicationGroupTranslator replicationGroupTranslator() {
            return null;
        }
    }

}
