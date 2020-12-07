// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-1.0
package org.stratumproject.fabric.tna.behaviour.pipeliner;

import org.onlab.packet.IpPrefix;
import org.onlab.packet.MacAddress;
import org.onlab.packet.MplsLabel;
import org.onlab.packet.VlanId;
import org.onosproject.TestApplicationId;
import org.onosproject.core.ApplicationId;
import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.TrafficSelector;
import org.stratumproject.fabric.tna.behaviour.FabricCapabilities;

import static org.easymock.EasyMock.createNiceMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;

public class FabricPipelinerTest {
    static final ApplicationId APP_ID = TestApplicationId.create("FabricPipelinerTest");
    // TODO: re-enable support for xconnext
    // static final ApplicationId XCONNECT_APP_ID = TestApplicationId.create("FabricPipelinerTest.xconnect");
    static final DeviceId DEVICE_ID = DeviceId.deviceId("device:bmv2:11");
    static final int PRIORITY = 100;
    static final PortNumber PORT_1 = PortNumber.portNumber(1);
    static final PortNumber PORT_2 = PortNumber.portNumber(2);
    static final VlanId VLAN_100 = VlanId.vlanId("100");
    static final VlanId VLAN_200 = VlanId.vlanId("200");
    static final MacAddress HOST_MAC = MacAddress.valueOf("00:00:00:00:00:01");
    static final MacAddress ROUTER_MAC = MacAddress.valueOf("00:00:00:00:02:01");
    static final IpPrefix IPV4_UNICAST_ADDR = IpPrefix.valueOf("10.0.0.1/32");
    static final IpPrefix IPV4_MCAST_ADDR = IpPrefix.valueOf("224.0.0.1/32");
    static final IpPrefix IPV6_UNICAST_ADDR = IpPrefix.valueOf("2000::1/32");
    static final IpPrefix IPV6_MCAST_ADDR = IpPrefix.valueOf("ff00::1/32");
    static final MplsLabel MPLS_10 = MplsLabel.mplsLabel(10);
    static final Integer NEXT_ID_1 = 1;
    static final TrafficSelector VLAN_META = DefaultTrafficSelector.builder()
            .matchVlanId(VLAN_100)
            .build();

    FabricCapabilities capabilitiesHashed;
    // TODO: add profile with simple next or remove references
    // FabricCapabilities capabilitiesSimple;

    void doSetup() {
        this.capabilitiesHashed = createNiceMock(FabricCapabilities.class);
        // TODO: add profile with simple next or remove tests
       //  this.capabilitiesSimple = createNiceMock(FabricCapabilities.class);
        expect(capabilitiesHashed.hasHashedTable()).andReturn(true).anyTimes();
        expect(capabilitiesHashed.supportDoubleVlanTerm()).andReturn(true).anyTimes();
        // TODO: add profile with simple next or remove tests
        // expect(capabilitiesSimple.hasHashedTable()).andReturn(false).anyTimes();
        // expect(capabilitiesSimple.supportDoubleVlanTerm()).andReturn(true).anyTimes();
        replay(capabilitiesHashed);
        // replay(capabilitiesSimple);
    }
}
