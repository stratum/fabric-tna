package org.princeton.conquest;

import org.onosproject.net.pi.model.PiActionId;
import org.onosproject.net.pi.model.PiMatchFieldId;
import org.onosproject.net.pi.model.PiTableId;

import java.util.Set;

public class Constants {
    public static final String APP_NAME = "org.princeton.conquest-app";

    // P4 Constants
    public static final Set<Integer> MIRROR_SESSION_IDS = Set.of(400, 401, 402, 403);

    public static int CONQUEST_ETHERTYPE = 0x9001;

    public static int FLOW_SIZE_ORIGINAL_BIT_WIDTH = 32;
    public static int FLOW_SIZE_UPPER_BITS_DISCARDED = 5;  // how many least-significant bits are discarded
    public static int FLOW_SIZE_LOWER_BITS_DISCARDED = 8;  // how many most-significant bits are discarded

    public static int FLOW_SIZE_RANGE_MAX
            = (1 << (FLOW_SIZE_ORIGINAL_BIT_WIDTH -
            (FLOW_SIZE_UPPER_BITS_DISCARDED + FLOW_SIZE_LOWER_BITS_DISCARDED))) - 1;

    public static int QUEUE_DELAY_BIT_WIDTH = 18;

    public static int QUEUE_DELAY_RANGE_MAX = (1 << QUEUE_DELAY_BIT_WIDTH) - 1;

    // P4 Entities
    public static PiTableId REPORT_TRIGGER_TABLE = PiTableId.of("FabricEgress.conquest.tb_per_flow_action");

    public static PiMatchFieldId FLOW_SIZE_IN_QUEUE = PiMatchFieldId.of("snap_0");
    public static PiMatchFieldId QUEUE_DELAY = PiMatchFieldId.of("q_delay");
    public static PiMatchFieldId RANDOM_BITS = PiMatchFieldId.of("random_bits");
    public static PiMatchFieldId ECN_BITS = PiMatchFieldId.of("ecn");

    public static PiActionId NOP = PiActionId.of("FabricEgress.conquest.conq_nop");
    public static PiActionId DROP = PiActionId.of("FabricEgress.conquest.drop");
    public static PiActionId MARK_ECN = PiActionId.of("FabricEgress.conquest.mark_ECN");
    public static PiActionId TRIGGER_REPORT = PiActionId.of("FabricEgress.conquest.trigger_report");
    public static PiActionId NOT_TRIGGER_REPORT = PiActionId.of("FabricEgress.conquest.not_trigger_report");
}
