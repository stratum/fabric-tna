// Copyright 2019 Princeton Cabernet Research Group
// License: AGPLv3

#ifndef __CONQUEST__
#define __CONQUEST__


#define SKETCH_INC ((bit<32>) hdr.ipv4.total_len)

typedef bit<8> ip_protocol_t;
const ip_protocol_t IP_PROTOCOLS_ICMP = 1;
const ip_protocol_t IP_PROTOCOLS_TCP = 6;
const ip_protocol_t IP_PROTOCOLS_UDP = 17;


control ConQuestEgress(
    /* Fabric.p4 */
    inout parsed_headers_t hdr,
    inout fabric_egress_metadata_t eg_md,
    /* TNA */
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_intr_md_from_prsr,
    inout egress_intrinsic_metadata_for_deparser_t     eg_intr_dprs_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_intr_oport_md
    ) {


    action conq_nop(){
    }
    action drop(){
        eg_intr_dprs_md.drop_ctl = 0x1;
    }
    action mark_ECN(){
        hdr.ipv4.ecn=0x3;
    }
    

    //== Start: What time is it? How long is the queue?
    action prep_epochs(){
        bit<18> q_delay=eg_intr_md.deq_timedelta;
        eg_md.q_delay=q_delay;
        eg_md.num_snapshots_to_read= (bit<8>) (q_delay >> 14);
        // Note: in P4_14 the delay in queuing meta is 32 bits. In P4_16, to recover 32-bit queuing delay, you need to manually bridge a longer timestamp from ingress. 
    
        bit<48> d_i=eg_intr_md_from_prsr.global_tstamp;
        //bit<18> a_i=eg_intr_md.enq_tstamp;
        eg_md.snap_epoch=d_i[14+2-1:14];
        // floor(d_i / T) % h
    }
    
    action prep_reads(){
                eg_md.snap_0_row_0_read=0;
                eg_md.snap_0_row_1_read=0;
                eg_md.snap_1_row_0_read=0;
                eg_md.snap_1_row_1_read=0;
                eg_md.snap_2_row_0_read=0;
                eg_md.snap_2_row_1_read=0;
                eg_md.snap_3_row_0_read=0;
                eg_md.snap_3_row_1_read=0;
    }
    
    Random< bit<8> >() rng;
    action prep_random(){
        eg_md.random_bits = rng.get();
    }
    
    //== Prepare register access index options
    Register<bit<32>,_>(1) reg_cleaning_index;
    RegisterAction<bit<32>, _, bit<32>>(reg_cleaning_index) reg_cleaning_index_rw = {
        void apply(inout bit<32> val, out bit<32> rv) {
            rv = val;
            val = val + 1;
        }
    };
    action calc_cyclic_index(){
        eg_md.cyclic_index = (bit<8>) reg_cleaning_index_rw.execute(0);
    }
    
        Hash<bit<8>>(HashAlgorithm_t.CRC32) hash_0_TCP;  
        Hash<bit<8>>(HashAlgorithm_t.CRC32) hash_0_UDP;  
        Hash<bit<8>>(HashAlgorithm_t.CRC32) hash_0_Other;   
        Hash<bit<8>>(HashAlgorithm_t.CRC32) hash_1_TCP;  
        Hash<bit<8>>(HashAlgorithm_t.CRC32) hash_1_UDP;  
        Hash<bit<8>>(HashAlgorithm_t.CRC32) hash_1_Other;   
       
    action calc_hashed_index_TCP(){
           eg_md.hashed_index_row_0 = hash_0_TCP.get({
               3w3, hdr.ipv4.src_addr,
               4w13, hdr.ipv4.dst_addr,
               5w5, hdr.tcp.sport,
               6w39, hdr.tcp.dport
           });
           eg_md.hashed_index_row_1 = hash_1_TCP.get({
               3w7, hdr.ipv4.src_addr,
               3w6, hdr.ipv4.dst_addr,
               6w29, hdr.tcp.sport,
               3w4, hdr.tcp.dport
           });
    }
    action calc_hashed_index_UDP(){
           eg_md.hashed_index_row_0 = hash_0_UDP.get({
               6w47, hdr.ipv4.src_addr,
               4w13, hdr.ipv4.dst_addr,
               5w13, hdr.udp.sport,
               3w3, hdr.udp.dport
           });
           eg_md.hashed_index_row_1 = hash_1_UDP.get({
               6w52, hdr.ipv4.src_addr,
               5w3, hdr.ipv4.dst_addr,
               5w22, hdr.udp.sport,
               6w49, hdr.udp.dport
           });
    }
    action calc_hashed_index_Other(){
           eg_md.hashed_index_row_0 = hash_0_Other.get({
               4w4, hdr.ipv4.src_addr,
               5w12, hdr.ipv4.dst_addr,
               5w6, hdr.ipv4.protocol
           });
           eg_md.hashed_index_row_1 = hash_1_Other.get({
               5w19, hdr.ipv4.src_addr,
               5w26, hdr.ipv4.dst_addr,
               4w0, hdr.ipv4.protocol
           });
    }
    
    
    //== Deciding on using hashed-based or cyclic-based index
        action snap_0_select_index_hash(){
                eg_md.snap_0_row_0_index=eg_md.cyclic_index;
                eg_md.snap_0_row_1_index=eg_md.cyclic_index;
        }
        action snap_0_select_index_cyclic(){
                eg_md.snap_0_row_0_index=eg_md.hashed_index_row_0;
                eg_md.snap_0_row_1_index=eg_md.hashed_index_row_1;
        }
        table tb_snap_0_select_index {
            key = {
                eg_md.snap_epoch: exact;
            }
            actions = {
                snap_0_select_index_hash;
                snap_0_select_index_cyclic;
            }
            size = 2;
            default_action = snap_0_select_index_hash();
            const entries = {
               0 : snap_0_select_index_cyclic();
            }
        }
        action snap_1_select_index_hash(){
                eg_md.snap_1_row_0_index=eg_md.cyclic_index;
                eg_md.snap_1_row_1_index=eg_md.cyclic_index;
        }
        action snap_1_select_index_cyclic(){
                eg_md.snap_1_row_0_index=eg_md.hashed_index_row_0;
                eg_md.snap_1_row_1_index=eg_md.hashed_index_row_1;
        }
        table tb_snap_1_select_index {
            key = {
                eg_md.snap_epoch: exact;
            }
            actions = {
                snap_1_select_index_hash;
                snap_1_select_index_cyclic;
            }
            size = 2;
            default_action = snap_1_select_index_hash();
            const entries = {
               1 : snap_1_select_index_cyclic();
            }
        }
        action snap_2_select_index_hash(){
                eg_md.snap_2_row_0_index=eg_md.cyclic_index;
                eg_md.snap_2_row_1_index=eg_md.cyclic_index;
        }
        action snap_2_select_index_cyclic(){
                eg_md.snap_2_row_0_index=eg_md.hashed_index_row_0;
                eg_md.snap_2_row_1_index=eg_md.hashed_index_row_1;
        }
        table tb_snap_2_select_index {
            key = {
                eg_md.snap_epoch: exact;
            }
            actions = {
                snap_2_select_index_hash;
                snap_2_select_index_cyclic;
            }
            size = 2;
            default_action = snap_2_select_index_hash();
            const entries = {
               2 : snap_2_select_index_cyclic();
            }
        }
        action snap_3_select_index_hash(){
                eg_md.snap_3_row_0_index=eg_md.cyclic_index;
                eg_md.snap_3_row_1_index=eg_md.cyclic_index;
        }
        action snap_3_select_index_cyclic(){
                eg_md.snap_3_row_0_index=eg_md.hashed_index_row_0;
                eg_md.snap_3_row_1_index=eg_md.hashed_index_row_1;
        }
        table tb_snap_3_select_index {
            key = {
                eg_md.snap_epoch: exact;
            }
            actions = {
                snap_3_select_index_hash;
                snap_3_select_index_cyclic;
            }
            size = 2;
            default_action = snap_3_select_index_hash();
            const entries = {
               3 : snap_3_select_index_cyclic();
            }
        }
    
    
    //== Prepare snapshot register access actions 
            Register<bit<32>,_>(256) snap_0_row_0;
            RegisterAction<bit<32>, _, bit<32>> (snap_0_row_0) snap_0_row_0_read = {
                    void apply(inout bit<32> val, out bit<32> rv) {
                        rv = val;
                    }
                };
            action regexec_snap_0_row_0_read(){
                eg_md.snap_0_row_0_read=snap_0_row_0_read.execute(eg_md.snap_0_row_0_index);
            }
            RegisterAction<bit<32>, _, bit<32>> (snap_0_row_0) snap_0_row_0_inc = {
                    void apply(inout bit<32> val, out bit<32> rv) {
                        val = val + SKETCH_INC;
                        rv = val;
                    }
                };
            action regexec_snap_0_row_0_inc(){
                eg_md.snap_0_row_0_read=snap_0_row_0_inc.execute(eg_md.snap_0_row_0_index);
            }
            RegisterAction<bit<32>, _, bit<32>> (snap_0_row_0) snap_0_row_0_clr = {
                    void apply(inout bit<32> val, out bit<32> rv) {
                        val = 0;
                        rv = 0;
                    }
                };
            action regexec_snap_0_row_0_clr(){
                snap_0_row_0_clr.execute(eg_md.snap_0_row_0_index);
            }
            table tb_snap_0_row_0_rr {
                key = {
                    eg_md.snap_epoch: exact;
                    eg_md.num_snapshots_to_read: range;
                }
                actions = {
                    regexec_snap_0_row_0_read;
                    regexec_snap_0_row_0_inc;
                    regexec_snap_0_row_0_clr;
                    conq_nop;
                }
                size = 17;
                default_action = conq_nop();
                //round-robin logic
                const entries = {
                    (0, 0..255) : regexec_snap_0_row_0_clr;
                    (1, 0..255) : regexec_snap_0_row_0_inc;
                    //read only when qlen/T is large enough (otherwise leave 0)
                        (2, 1..255) : regexec_snap_0_row_0_read;
                        (3, 2..255) : regexec_snap_0_row_0_read;
                }
            }
            Register<bit<32>,_>(256) snap_0_row_1;
            RegisterAction<bit<32>, _, bit<32>> (snap_0_row_1) snap_0_row_1_read = {
                    void apply(inout bit<32> val, out bit<32> rv) {
                        rv = val;
                    }
                };
            action regexec_snap_0_row_1_read(){
                eg_md.snap_0_row_1_read=snap_0_row_1_read.execute(eg_md.snap_0_row_1_index);
            }
            RegisterAction<bit<32>, _, bit<32>> (snap_0_row_1) snap_0_row_1_inc = {
                    void apply(inout bit<32> val, out bit<32> rv) {
                        val = val + SKETCH_INC;
                        rv = val;
                    }
                };
            action regexec_snap_0_row_1_inc(){
                eg_md.snap_0_row_1_read=snap_0_row_1_inc.execute(eg_md.snap_0_row_1_index);
            }
            RegisterAction<bit<32>, _, bit<32>> (snap_0_row_1) snap_0_row_1_clr = {
                    void apply(inout bit<32> val, out bit<32> rv) {
                        val = 0;
                        rv = 0;
                    }
                };
            action regexec_snap_0_row_1_clr(){
                snap_0_row_1_clr.execute(eg_md.snap_0_row_1_index);
            }
            table tb_snap_0_row_1_rr {
                key = {
                    eg_md.snap_epoch: exact;
                    eg_md.num_snapshots_to_read: range;
                }
                actions = {
                    regexec_snap_0_row_1_read;
                    regexec_snap_0_row_1_inc;
                    regexec_snap_0_row_1_clr;
                    conq_nop;
                }
                size = 17;
                default_action = conq_nop();
                //round-robin logic
                const entries = {
                    (0, 0..255) : regexec_snap_0_row_1_clr;
                    (1, 0..255) : regexec_snap_0_row_1_inc;
                    //read only when qlen/T is large enough (otherwise leave 0)
                        (2, 1..255) : regexec_snap_0_row_1_read;
                        (3, 2..255) : regexec_snap_0_row_1_read;
                }
            }
            Register<bit<32>,_>(256) snap_1_row_0;
            RegisterAction<bit<32>, _, bit<32>> (snap_1_row_0) snap_1_row_0_read = {
                    void apply(inout bit<32> val, out bit<32> rv) {
                        rv = val;
                    }
                };
            action regexec_snap_1_row_0_read(){
                eg_md.snap_1_row_0_read=snap_1_row_0_read.execute(eg_md.snap_1_row_0_index);
            }
            RegisterAction<bit<32>, _, bit<32>> (snap_1_row_0) snap_1_row_0_inc = {
                    void apply(inout bit<32> val, out bit<32> rv) {
                        val = val + SKETCH_INC;
                        rv = val;
                    }
                };
            action regexec_snap_1_row_0_inc(){
                eg_md.snap_1_row_0_read=snap_1_row_0_inc.execute(eg_md.snap_1_row_0_index);
            }
            RegisterAction<bit<32>, _, bit<32>> (snap_1_row_0) snap_1_row_0_clr = {
                    void apply(inout bit<32> val, out bit<32> rv) {
                        val = 0;
                        rv = 0;
                    }
                };
            action regexec_snap_1_row_0_clr(){
                snap_1_row_0_clr.execute(eg_md.snap_1_row_0_index);
            }
            table tb_snap_1_row_0_rr {
                key = {
                    eg_md.snap_epoch: exact;
                    eg_md.num_snapshots_to_read: range;
                }
                actions = {
                    regexec_snap_1_row_0_read;
                    regexec_snap_1_row_0_inc;
                    regexec_snap_1_row_0_clr;
                    conq_nop;
                }
                size = 17;
                default_action = conq_nop();
                //round-robin logic
                const entries = {
                    (1, 0..255) : regexec_snap_1_row_0_clr;
                    (2, 0..255) : regexec_snap_1_row_0_inc;
                    //read only when qlen/T is large enough (otherwise leave 0)
                        (3, 1..255) : regexec_snap_1_row_0_read;
                        (0, 2..255) : regexec_snap_1_row_0_read;
                }
            }
            Register<bit<32>,_>(256) snap_1_row_1;
            RegisterAction<bit<32>, _, bit<32>> (snap_1_row_1) snap_1_row_1_read = {
                    void apply(inout bit<32> val, out bit<32> rv) {
                        rv = val;
                    }
                };
            action regexec_snap_1_row_1_read(){
                eg_md.snap_1_row_1_read=snap_1_row_1_read.execute(eg_md.snap_1_row_1_index);
            }
            RegisterAction<bit<32>, _, bit<32>> (snap_1_row_1) snap_1_row_1_inc = {
                    void apply(inout bit<32> val, out bit<32> rv) {
                        val = val + SKETCH_INC;
                        rv = val;
                    }
                };
            action regexec_snap_1_row_1_inc(){
                eg_md.snap_1_row_1_read=snap_1_row_1_inc.execute(eg_md.snap_1_row_1_index);
            }
            RegisterAction<bit<32>, _, bit<32>> (snap_1_row_1) snap_1_row_1_clr = {
                    void apply(inout bit<32> val, out bit<32> rv) {
                        val = 0;
                        rv = 0;
                    }
                };
            action regexec_snap_1_row_1_clr(){
                snap_1_row_1_clr.execute(eg_md.snap_1_row_1_index);
            }
            table tb_snap_1_row_1_rr {
                key = {
                    eg_md.snap_epoch: exact;
                    eg_md.num_snapshots_to_read: range;
                }
                actions = {
                    regexec_snap_1_row_1_read;
                    regexec_snap_1_row_1_inc;
                    regexec_snap_1_row_1_clr;
                    conq_nop;
                }
                size = 17;
                default_action = conq_nop();
                //round-robin logic
                const entries = {
                    (1, 0..255) : regexec_snap_1_row_1_clr;
                    (2, 0..255) : regexec_snap_1_row_1_inc;
                    //read only when qlen/T is large enough (otherwise leave 0)
                        (3, 1..255) : regexec_snap_1_row_1_read;
                        (0, 2..255) : regexec_snap_1_row_1_read;
                }
            }
            Register<bit<32>,_>(256) snap_2_row_0;
            RegisterAction<bit<32>, _, bit<32>> (snap_2_row_0) snap_2_row_0_read = {
                    void apply(inout bit<32> val, out bit<32> rv) {
                        rv = val;
                    }
                };
            action regexec_snap_2_row_0_read(){
                eg_md.snap_2_row_0_read=snap_2_row_0_read.execute(eg_md.snap_2_row_0_index);
            }
            RegisterAction<bit<32>, _, bit<32>> (snap_2_row_0) snap_2_row_0_inc = {
                    void apply(inout bit<32> val, out bit<32> rv) {
                        val = val + SKETCH_INC;
                        rv = val;
                    }
                };
            action regexec_snap_2_row_0_inc(){
                eg_md.snap_2_row_0_read=snap_2_row_0_inc.execute(eg_md.snap_2_row_0_index);
            }
            RegisterAction<bit<32>, _, bit<32>> (snap_2_row_0) snap_2_row_0_clr = {
                    void apply(inout bit<32> val, out bit<32> rv) {
                        val = 0;
                        rv = 0;
                    }
                };
            action regexec_snap_2_row_0_clr(){
                snap_2_row_0_clr.execute(eg_md.snap_2_row_0_index);
            }
            table tb_snap_2_row_0_rr {
                key = {
                    eg_md.snap_epoch: exact;
                    eg_md.num_snapshots_to_read: range;
                }
                actions = {
                    regexec_snap_2_row_0_read;
                    regexec_snap_2_row_0_inc;
                    regexec_snap_2_row_0_clr;
                    conq_nop;
                }
                size = 17;
                default_action = conq_nop();
                //round-robin logic
                const entries = {
                    (2, 0..255) : regexec_snap_2_row_0_clr;
                    (3, 0..255) : regexec_snap_2_row_0_inc;
                    //read only when qlen/T is large enough (otherwise leave 0)
                        (0, 1..255) : regexec_snap_2_row_0_read;
                        (1, 2..255) : regexec_snap_2_row_0_read;
                }
            }
            Register<bit<32>,_>(256) snap_2_row_1;
            RegisterAction<bit<32>, _, bit<32>> (snap_2_row_1) snap_2_row_1_read = {
                    void apply(inout bit<32> val, out bit<32> rv) {
                        rv = val;
                    }
                };
            action regexec_snap_2_row_1_read(){
                eg_md.snap_2_row_1_read=snap_2_row_1_read.execute(eg_md.snap_2_row_1_index);
            }
            RegisterAction<bit<32>, _, bit<32>> (snap_2_row_1) snap_2_row_1_inc = {
                    void apply(inout bit<32> val, out bit<32> rv) {
                        val = val + SKETCH_INC;
                        rv = val;
                    }
                };
            action regexec_snap_2_row_1_inc(){
                eg_md.snap_2_row_1_read=snap_2_row_1_inc.execute(eg_md.snap_2_row_1_index);
            }
            RegisterAction<bit<32>, _, bit<32>> (snap_2_row_1) snap_2_row_1_clr = {
                    void apply(inout bit<32> val, out bit<32> rv) {
                        val = 0;
                        rv = 0;
                    }
                };
            action regexec_snap_2_row_1_clr(){
                snap_2_row_1_clr.execute(eg_md.snap_2_row_1_index);
            }
            table tb_snap_2_row_1_rr {
                key = {
                    eg_md.snap_epoch: exact;
                    eg_md.num_snapshots_to_read: range;
                }
                actions = {
                    regexec_snap_2_row_1_read;
                    regexec_snap_2_row_1_inc;
                    regexec_snap_2_row_1_clr;
                    conq_nop;
                }
                size = 17;
                default_action = conq_nop();
                //round-robin logic
                const entries = {
                    (2, 0..255) : regexec_snap_2_row_1_clr;
                    (3, 0..255) : regexec_snap_2_row_1_inc;
                    //read only when qlen/T is large enough (otherwise leave 0)
                        (0, 1..255) : regexec_snap_2_row_1_read;
                        (1, 2..255) : regexec_snap_2_row_1_read;
                }
            }
            Register<bit<32>,_>(256) snap_3_row_0;
            RegisterAction<bit<32>, _, bit<32>> (snap_3_row_0) snap_3_row_0_read = {
                    void apply(inout bit<32> val, out bit<32> rv) {
                        rv = val;
                    }
                };
            action regexec_snap_3_row_0_read(){
                eg_md.snap_3_row_0_read=snap_3_row_0_read.execute(eg_md.snap_3_row_0_index);
            }
            RegisterAction<bit<32>, _, bit<32>> (snap_3_row_0) snap_3_row_0_inc = {
                    void apply(inout bit<32> val, out bit<32> rv) {
                        val = val + SKETCH_INC;
                        rv = val;
                    }
                };
            action regexec_snap_3_row_0_inc(){
                eg_md.snap_3_row_0_read=snap_3_row_0_inc.execute(eg_md.snap_3_row_0_index);
            }
            RegisterAction<bit<32>, _, bit<32>> (snap_3_row_0) snap_3_row_0_clr = {
                    void apply(inout bit<32> val, out bit<32> rv) {
                        val = 0;
                        rv = 0;
                    }
                };
            action regexec_snap_3_row_0_clr(){
                snap_3_row_0_clr.execute(eg_md.snap_3_row_0_index);
            }
            table tb_snap_3_row_0_rr {
                key = {
                    eg_md.snap_epoch: exact;
                    eg_md.num_snapshots_to_read: range;
                }
                actions = {
                    regexec_snap_3_row_0_read;
                    regexec_snap_3_row_0_inc;
                    regexec_snap_3_row_0_clr;
                    conq_nop;
                }
                size = 17;
                default_action = conq_nop();
                //round-robin logic
                const entries = {
                    (3, 0..255) : regexec_snap_3_row_0_clr;
                    (0, 0..255) : regexec_snap_3_row_0_inc;
                    //read only when qlen/T is large enough (otherwise leave 0)
                        (1, 1..255) : regexec_snap_3_row_0_read;
                        (2, 2..255) : regexec_snap_3_row_0_read;
                }
            }
            Register<bit<32>,_>(256) snap_3_row_1;
            RegisterAction<bit<32>, _, bit<32>> (snap_3_row_1) snap_3_row_1_read = {
                    void apply(inout bit<32> val, out bit<32> rv) {
                        rv = val;
                    }
                };
            action regexec_snap_3_row_1_read(){
                eg_md.snap_3_row_1_read=snap_3_row_1_read.execute(eg_md.snap_3_row_1_index);
            }
            RegisterAction<bit<32>, _, bit<32>> (snap_3_row_1) snap_3_row_1_inc = {
                    void apply(inout bit<32> val, out bit<32> rv) {
                        val = val + SKETCH_INC;
                        rv = val;
                    }
                };
            action regexec_snap_3_row_1_inc(){
                eg_md.snap_3_row_1_read=snap_3_row_1_inc.execute(eg_md.snap_3_row_1_index);
            }
            RegisterAction<bit<32>, _, bit<32>> (snap_3_row_1) snap_3_row_1_clr = {
                    void apply(inout bit<32> val, out bit<32> rv) {
                        val = 0;
                        rv = 0;
                    }
                };
            action regexec_snap_3_row_1_clr(){
                snap_3_row_1_clr.execute(eg_md.snap_3_row_1_index);
            }
            table tb_snap_3_row_1_rr {
                key = {
                    eg_md.snap_epoch: exact;
                    eg_md.num_snapshots_to_read: range;
                }
                actions = {
                    regexec_snap_3_row_1_read;
                    regexec_snap_3_row_1_inc;
                    regexec_snap_3_row_1_clr;
                    conq_nop;
                }
                size = 17;
                default_action = conq_nop();
                //round-robin logic
                const entries = {
                    (3, 0..255) : regexec_snap_3_row_1_clr;
                    (0, 0..255) : regexec_snap_3_row_1_inc;
                    //read only when qlen/T is large enough (otherwise leave 0)
                        (1, 1..255) : regexec_snap_3_row_1_read;
                        (2, 2..255) : regexec_snap_3_row_1_read;
                }
            }
  
    
    //== Folding sums, which can't be written inline 
            action calc_sum_0_l0(){
                eg_md.snap_0_read_min_l1 = 
                eg_md.snap_0_read_min_l0 + eg_md.snap_1_read_min_l0;
            }
            action calc_sum_2_l0(){
                eg_md.snap_2_read_min_l1 = 
                eg_md.snap_2_read_min_l0 + eg_md.snap_3_read_min_l0;
            }
  
            action calc_sum_0_l1(){
                eg_md.snap_0_read_min_l2 = 
                eg_md.snap_0_read_min_l1 + eg_md.snap_2_read_min_l1;
            }

    action trigger_report() {
        eg_md.send_conq_report = 1;
    }
  
    
    //== Finally, actions based on flow size in the queue
    table tb_per_flow_action {
        key = {
            eg_md.snap_0_read_min_l2[26:10]: range      @name("snap_0"); //scale down to 16 bits
            eg_md.q_delay: range                        @name("q_delay");
            eg_md.random_bits: range                    @name("random_bits");
            hdr.ipv4.ecn : exact                        @name("ecn");
        }
        actions = {
            conq_nop;
            drop;
            mark_ECN;
            trigger_report;
        }
        default_action = conq_nop();
        // const entries = {  }
    }

    action generate_report_common() {
        eg_intr_dprs_md.mirror_type = (bit<3>)FabricMirrorType_t.CONQ_REPORT;
        eg_md.conq_mirror_md.setValid();
        eg_md.conq_mirror_md.protocol = hdr.ipv4.protocol;
        eg_md.conq_mirror_md.sip = hdr.ipv4.src;
        eg_md.conq_mirror_md.dip = hdr.ipv4.dst;
        // clone here
    }

    action generate_report_from_tcp() {
        generate_report_common();
        eg_md.conq_mirror_md.sport = hdr.tcp.sport;
        eg_md.conq_mirror_md.dport = hdr.tcp.dport;
    }

    action generate_report_from_udp() {
        generate_report_common();
        eg_md.conq_mirror_md.sport = hdr.udp.sport;
        eg_md.conq_mirror_md.dport = hdr.udp.dport;
    }

    action generate_report_from_unknown() {
        generate_report_common();
        eg_md.conq_mirror_md.sport = 0;
        eg_md.conq_mirror_md.dport = 0;
    }


    table report_generator() {
        key = {
            hdr.tcp.isValid(): exact;
            hdr.udp.isValid(): exact;
        }
        actions = {
            generate_report_from_inner;
            generate_report_from_outer;
            generate_report_from_unknown;
        }
        const entries = {
            (1, 0): generate_report_from_tcp();
            (0, 1): generate_report_from_udp();
            (0, 0): generate_report_from_unknown();
        }

    }

    @hidden
    action set_mirror_session_id(MirrorId_t sid) {
        eg_md.conq_mirror_md.mirror_session_id = sid;
    }

    @hidden
    table mirror_session_id {
        key = {
            eg_intr_md.egress_port: ternary;
        }
        actions = {
            set_mirror_session_id;
        }
        size = 4;
        const entries = {
            PIPE_0_PORTS_MATCH: set_mirror_session_id(CONQUEST_MIRROR_SESS_PIPE_0);
            PIPE_1_PORTS_MATCH: set_mirror_session_id(CONQUEST_MIRROR_SESS_PIPE_1);
            PIPE_2_PORTS_MATCH: set_mirror_session_id(CONQUEST_MIRROR_SESS_PIPE_2);
            PIPE_3_PORTS_MATCH: set_mirror_session_id(CONQUEST_MIRROR_SESS_PIPE_3);
        }
    }
    
    apply {
        // Startup
        prep_epochs();
        prep_reads();
        prep_random();
        
        // Index for sketch cleaning and read/write
        calc_cyclic_index();
        if(hdr.ipv4.protocol==IP_PROTOCOLS_TCP){
            calc_hashed_index_TCP();
        }else if(hdr.ipv4.protocol==IP_PROTOCOLS_UDP){
            calc_hashed_index_UDP();
        }else{
            calc_hashed_index_Other();
        }
        
        // Select index for snapshots. Cyclic for cleaning, hashed for read/inc
            tb_snap_0_select_index.apply();
            tb_snap_1_select_index.apply();
            tb_snap_2_select_index.apply();
            tb_snap_3_select_index.apply();
   
        
        // Run the snapshots! Round-robin clean, inc, read
                 tb_snap_0_row_0_rr.apply();
                 tb_snap_0_row_1_rr.apply();
                 tb_snap_1_row_0_rr.apply();
                 tb_snap_1_row_1_rr.apply();
                 tb_snap_2_row_0_rr.apply();
                 tb_snap_2_row_1_rr.apply();
                 tb_snap_3_row_0_rr.apply();
                 tb_snap_3_row_1_rr.apply();
   
        
        // Calc min across rows (as in count-"min" sketch)
                eg_md.snap_0_read_min_l0=min(eg_md.snap_0_row_0_read,eg_md.snap_0_row_1_read);
                eg_md.snap_1_read_min_l0=min(eg_md.snap_1_row_0_read,eg_md.snap_1_row_1_read);
                eg_md.snap_2_read_min_l0=min(eg_md.snap_2_row_0_read,eg_md.snap_2_row_1_read);
                eg_md.snap_3_read_min_l0=min(eg_md.snap_3_row_0_read,eg_md.snap_3_row_1_read);
   
        
        // Sum all reads together, using log(CQ_H) layers.
                calc_sum_0_l0();
                calc_sum_2_l0();
  
                calc_sum_0_l1();
  
  
        // bit<32> snap_read_sum=eg_md.snap_0_read_min_l2;
        
        // With flow size in queue, can check for bursty flow and add AQM.
        tb_per_flow_action.apply();
        if (eg_md.send_conq_report) {
            report_generator.apply();
            mirror_session_id.apply();
        }
    }
}
#endif // __CONQUEST__
