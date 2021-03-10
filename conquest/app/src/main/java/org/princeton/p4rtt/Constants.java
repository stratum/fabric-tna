package org.princeton.p4rtt;

import com.google.common.collect.ImmutableMap;
import org.onosproject.net.pi.model.PiActionId;
import org.onosproject.net.pi.model.PiActionParamId;
import org.onosproject.net.pi.model.PiMatchFieldId;
import org.onosproject.net.pi.model.PiTableId;

import java.util.Map;
import java.util.Set;

public class Constants {
    public static final String APP_NAME = "org.princeton.p4rtt-app";

    public static final Set<Integer> MIRROR_SESSION_IDS =
            Set.of(400, 401, 402, 403);

    // P4 Constants
    public static int P4RTT_TYPE_SEQ = 1;
    public static int P4RTT_TYPE_ACK = 2;
    public static int P4RTT_TYPE_IGN = 0;
    public static int CONQUEST_ETHERTYPE = 0x9001;

    // P4 Entity names
    public static PiTableId MATCH_TYPE_TABLE = PiTableId.of("FabricIngress.p4_rtt_control.match_type");
    public static PiMatchFieldId IPV4_SRC_KEY = PiMatchFieldId.of("ipv4_src");
    public static PiMatchFieldId IPV4_DST_KEY = PiMatchFieldId.of("ipv4_dst");
    public static PiMatchFieldId IPV4_PROTO_KEY = PiMatchFieldId.of("ipv4_proto");
    public static PiActionId SET_TYPE_ACTION = PiActionId.of("FabricIngress.p4_rtt_control.set_type");
    public static PiActionParamId SET_TYPE_PARAM = PiActionParamId.of("t");
}
