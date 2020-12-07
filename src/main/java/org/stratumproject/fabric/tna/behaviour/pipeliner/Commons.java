// Copyright 2018-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-1.0

package org.stratumproject.fabric.tna.behaviour.pipeliner;

import org.onlab.packet.EthType;
import org.onlab.packet.MacAddress;
import org.onosproject.net.flow.criteria.Criteria;
import org.onosproject.net.flow.criteria.Criterion;

/**
 * Constants common to ForwardingFunctionType operations.
 */
final class Commons {

    static final Criterion MATCH_ETH_TYPE_IPV4 = Criteria.matchEthType(
      EthType.EtherType.IPV4.ethType());
    static final Criterion MATCH_ETH_TYPE_IPV6 = Criteria.matchEthType(
      EthType.EtherType.IPV6.ethType());
    static final Criterion MATCH_ETH_DST_NONE = Criteria.matchEthDst(
      MacAddress.NONE);
    static final Criterion MATCH_ETH_TYPE_MPLS = Criteria.matchEthType(
      EthType.EtherType.MPLS_UNICAST.ethType());
    static final Criterion MATCH_MPLS_BOS_TRUE = Criteria.matchMplsBos(true);
    static final Criterion MATCH_MPLS_BOS_FALSE = Criteria.matchMplsBos(false);

    private Commons() {
        // hides constructor.
    }
}
