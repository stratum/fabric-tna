#!/usr/bin/env python3

# Copyright 2013-2018 Barefoot Networks, Inc.
# Copyright 2018-present Open Networking Foundation
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0 AND Apache-2.0

import argparse
import json
import logging
import os
import queue
import re
import subprocess
import sys
import threading
import time
from collections import OrderedDict

import google.protobuf.text_format
import grpc
from p4.v1 import p4runtime_pb2, p4runtime_pb2_grpc

# PTF-to-TestVector translation utils
# https://github.com/stratum/testvectors/tree/master/utils/python
from portmap import pmutils
from target import targetutils
from testvector import tvutils

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("PTF runner")


def error(msg, *args, **kwargs):
    logger.error(msg, *args, **kwargs)


def warn(msg, *args, **kwargs):
    logger.warn(msg, *args, **kwargs)


def info(msg, *args, **kwargs):
    logger.info(msg, *args, **kwargs)


def check_ifaces(ifaces):
    """
    Checks that required interfaces exist.
    """
    ifconfig_out = subprocess.check_output(["ifconfig"]).decode("utf-8")
    iface_list = re.findall(r"^([a-zA-Z0-9]+)", ifconfig_out, re.S | re.M)
    present_ifaces = set(iface_list)
    ifaces = set(ifaces)
    return ifaces <= present_ifaces


def build_tofino_pipeline_config(tofino_pipeline_config_path):
    device_config = b""
    with open(tofino_pipeline_config_path, "rb") as pipeline_config_f:
        device_config += pipeline_config_f.read()
    return device_config


def update_config(
    p4info_path, tofino_pipeline_config_path, grpc_addr, device_id, generate_tv=False,
):
    """
    Performs a SetForwardingPipelineConfig on the device
    """
    # Build pipeline config request
    request = p4runtime_pb2.SetForwardingPipelineConfigRequest()
    request.device_id = device_id
    election_id = request.election_id
    election_id.high = 0
    election_id.low = 1
    config = request.config
    with open(p4info_path, "r") as p4info_f:
        google.protobuf.text_format.Merge(p4info_f.read(), config.p4info)
    device_config = build_tofino_pipeline_config(tofino_pipeline_config_path)
    config.p4_device_config = device_config
    request.action = p4runtime_pb2.SetForwardingPipelineConfigRequest.VERIFY_AND_COMMIT

    if generate_tv:
        # Create new target proto object for testvectors
        tv_target = targetutils.get_new_target(grpc_addr, target_id="tofino")
        # Write the target proto object to testvectors/target.pb.txt
        targetutils.write_to_file(tv_target, os.getcwd())
        # Create new testvector for set pipeline config and write to
        # testvectors/PipelineConfig.pb.txt
        tv = tvutils.get_new_testvector()
        tv_name = "PipelineConfig"
        tc = tvutils.get_new_testcase(tv, tv_name)
        tvutils.add_pipeline_config_operation(tc, request)
        tvutils.write_to_file(tv, os.getcwd(), tv_name)
        return True
    channel = grpc.insecure_channel(grpc_addr)
    stub = p4runtime_pb2_grpc.P4RuntimeStub(channel)

    info("Sending P4 config")

    # Send master arbitration via stream channel
    # This should go in library, to be re-used also by base_test.py.
    stream_out_q = queue.Queue()
    stream_in_q = queue.Queue()

    def stream_req_iterator():
        while True:
            p = stream_out_q.get()
            if p is None:
                break
            yield p

    def stream_recv(stream):
        for p in stream:
            stream_in_q.put(p)

    def get_stream_packet(type_, timeout=1):
        start = time.time()
        try:
            while True:
                remaining = timeout - (time.time() - start)
                if remaining < 0:
                    break
                msg = stream_in_q.get(timeout=remaining)
                if not msg.HasField(type_):
                    continue
                return msg
        except Exception:  # timeout expired
            pass
        return None

    stream = stub.StreamChannel(stream_req_iterator())
    stream_recv_thread = threading.Thread(target=stream_recv, args=(stream,))
    stream_recv_thread.start()

    req = p4runtime_pb2.StreamMessageRequest()
    arbitration = req.arbitration
    arbitration.device_id = device_id
    election_id = arbitration.election_id
    election_id.high = 0
    election_id.low = 1
    stream_out_q.put(req)

    rep = get_stream_packet("arbitration", timeout=5)
    if rep is None:
        error("Failed to establish handshake")
        return False

    try:
        try:
            stub.SetForwardingPipelineConfig(request)
        except Exception as e:
            error("Error during SetForwardingPipelineConfig")
            error(str(e))
            return False
        return True
    finally:
        stream_out_q.put(None)
        stream_recv_thread.join()


def run_test(
    p4info_path,
    grpc_addr,
    device_id,
    cpu_port,
    ptfdir,
    port_map_path,
    profile,
    platform=None,
    generate_tv=False,
    loopback=False,
    trex_address=None,
    extra_args=()
):
    """
    Runs PTF tests included in provided directory.
    Device must be running and configfured with appropriate P4 program.
    """
    # TODO: figure out what I'm supposed to do here if it is a trex test

    # TODO: check schema?
    # "ptf_port" is ignored for now, we assume that ports are provided by
    # increasing values of ptf_port, in the range [0, NUM_IFACES].
    port_map = OrderedDict()
    # If not a line-rate test, skip opening and parsing the JSON port map
    if trex_address is None:
        with open(port_map_path, "r") as port_map_f:
            port_list = json.load(port_map_f)
            if generate_tv:
                # interfaces string to be used to create interfaces in test runner
                # container
                interfaces = ""
                # Create new portmap proto object for testvectors
                tv_portmap = pmutils.get_new_portmap()
            for entry in port_list:
                p4_port = entry["p4_port"]
                iface_name = entry["iface_name"]
                port_map[p4_port] = iface_name
                if generate_tv:
                    # Append iface_name to interfaces
                    interfaces = interfaces + " " + iface_name
                    # Append new entry to tv proto object
                    pmutils.add_new_entry(tv_portmap, p4_port, iface_name)
    if generate_tv:
        # ptf needs the interfaces mentioned in portmap to be running on
        # container
        # For generate_tv option, we don't strat tofino model container
        # This is a work around to create those interfaces on testrunner
        # contiainer
        try:
            cmd = os.getcwd() + "/../../run/tv/setup_interfaces.sh" + interfaces
            p = subprocess.Popen([cmd], shell=True)
            p.wait()
        except Exception as e:
            print(e)
            error("Error when creating interfaces")
            return False
        # Write the portmap proto object to testvectors/portmap.pb.txt
        pmutils.write_to_file(tv_portmap, os.getcwd())

    if not generate_tv and not check_ifaces(port_map.values()):
        error("Some interfaces are missing")
        return False

    ifaces = []
    # FIXME
    # find base_test.py
    pypath = os.path.dirname(os.path.abspath(__file__))
    if "PYTHONPATH" in os.environ:
        os.environ["PYTHONPATH"] += ":" + pypath
    else:
        os.environ["PYTHONPATH"] = pypath
    for iface_idx, iface_name in port_map.items():
        ifaces.extend(["-i", "{}@{}".format(iface_idx, iface_name)])
    cmd = ["ptf"]
    cmd.extend(["--test-dir", ptfdir])
    cmd.extend(ifaces)
    test_params = "p4info='{}'".format(p4info_path)
    test_params += ";grpcaddr='{}'".format(grpc_addr)
    test_params += ";device_id='{}'".format(device_id)
    test_params += ";cpu_port='{}'".format(cpu_port)
    test_params += ";generate_tv='{}'".format(generate_tv)
    test_params += ";loopback='{}'".format(loopback)
    if platform is not None:
        test_params += ";pltfm='{}'".format(platform)
    test_params += ";profile='{}'".format(profile)
    cmd.append("--test-params={}".format(test_params))
    cmd.extend(extra_args)
    info("Executing PTF command: {}".format(" ".join(cmd)))

    try:
        # we want the ptf output to be sent to stdout
        p = subprocess.Popen(cmd)
        p.wait()
    except Exception:
        error("Error when running PTF tests")
        return False
    return p.returncode == 0


def check_ptf():
    try:
        with open(os.devnull, "w") as devnull:
            subprocess.check_call(["ptf", "--version"], stdout=devnull, stderr=devnull)
        return True
    except subprocess.CalledProcessError:
        return True
    except OSError:  # PTF not found
        return False


TREX_FILES_DIR = "/tmp/trex_files/"
trex_daemon_client = None


def set_up_trex_server(trex_address, trex_config, force_restart):
    # Init trex client
    trex_daemon_client = CTRexClient(trex_address)

    # Push TRex config to server
    logging.info("Pushing Trex config %s to the server", trex_config)
    if not trex_daemon_client.push_files(trex_config):
        logging.error("Unable to push %s to Trex server", trex_config)
        return 1

    # Restart client if specified
    if force_restart:
        logging.info("Killing all Trexes... with meteorite... Boom!")
        trex_daemon_client.kill_all_trexes()

        # Wait until Trex enter the Idle state
        start_time = time.time()
        success = False
        while time.time() - start_time < DEFAULT_KILL_TIMEOUT:
            if trex_daemon_client.is_idle():
                success = True
                break
            time.sleep(1)

        if not success:
            logging.error(
                "Unable to kill Trex process, please login "
                + "to the server and kill it manually."
            )
            return 1

    # Check if daemon client already running
    if not trex_daemon_client.is_idle():
        logging.info("The Trex server process is running")
        logging.warning(
            "A Trex server process is still running, "
            + "use --force-restart to kill it if necessary."
        )
        return 1


    # Start daemon client on server
    trex_config_file_on_server = TREX_FILES_DIR + os.path.basename(trex_config)
    trex_daemon_client.start_trex(cfg=trex_config_file_on_server)


# noinspection PyTypeChecker
def main():
    parser = argparse.ArgumentParser(
        description="Compile the provided P4 program and run PTF tests on it"
    )
    parser.add_argument(
        "--p4info",
        help="Location of p4info proto in text format",
        type=str,
        action="store",
        required=True,
    )
    parser.add_argument(
        "--tofino-pipeline-config",
        help="Location of the Tofino pipeline config binary " "(pb.bin)",
        type=str,
        action="store",
        required=False,
    )
    parser.add_argument(
        "--grpc-addr",
        help="Address to use to connect to P4 Runtime server",
        type=str,
        default="localhost:50051",
    )
    parser.add_argument(
        "--device-id", help="Device id for device under test", type=int, default=1,
    )
    parser.add_argument(
        "--cpu-port", help="CPU port ID of device under test", type=int, required=True,
    )
    parser.add_argument(
        "--ptf-dir", help="Directory containing PTF tests", type=str, required=True,
    )
    parser.add_argument(
        "--port-map", help="Path to JSON port mapping", type=str, required=True
    )
    parser.add_argument(
        "--platform",
        help="Target platform on which tests are run " "(if target is tofino)",
        type=str,
        required=False,
    )
    parser.add_argument(
        "--skip-config",
        help="Skip configuring the pipeline to the device",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "--skip-test",
        help="Skip test execution " "(useful to perform only pipeline configuration)",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "--generate-tv",
        help="Skip test execution and generate TestVectors",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "--loopback",
        help="Flag to modify test data for loopback mode",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "--profile",
        help="The fabric profile",
        type=str,
        required=True,
        choices=["fabric", "fabric-spgw", "fabric-int", "fabric-spgw-int"],
    )

    parser.add_argument(
        "--trex-address",
        help="",
        type=str,
        required=False,
    )
    parser.add_argument(
        "--trex-config",
        help="",
        type=str,
        required=False,
    )
    # parser.add_argument(
    #     "--line-rate-test",
    #     help="",
    #     action="store_true",
    #     required=False,
    # )
    parser.add_argument(
        "--keep-trex-running",
        help="Keep TRex client running after the test",
        action="store_true",
        required=False,
    )

    parser.add_argument(
        "--force-restart",
        help="Force restart the Trex process if one running.",
        action="store_true",
        required=False,
    )

    args, unknown_args = parser.parse_known_args()

    if not check_ptf():
        error("Cannot find PTF executable")
        sys.exit(1)

    tofino_pipeline_config = None
    if not os.path.exists(args.p4info):
        error("P4Info file {} not found".format(args.p4info))
        sys.exit(1)
    if not os.path.exists(args.tofino_pipeline_config):
        error(
            "Tofino binary config file {} not found".format(args.tofino_pipeline_config)
        )
        sys.exit(1)
    tofino_pipeline_config = args.tofino_pipeline_config
    if not os.path.exists(args.port_map):
        print("Port map path '{}' does not exist".format(args.port_map))
        sys.exit(1)

    success = True

    if args.trex_address is not None:
        success = set_up_trex_server(args.trex_address, args.trex_config, args.force_restart)

    if not args.skip_config:
        success = update_config(
            p4info_path=args.p4info,
            tofino_pipeline_config_path=tofino_pipeline_config,
            grpc_addr=args.grpc_addr,
            device_id=args.device_id,
            generate_tv=args.generate_tv,
        )
    if not success:
        sys.exit(2)

    if not args.skip_test:
        success = run_test(
            p4info_path=args.p4info,
            device_id=args.device_id,
            grpc_addr=args.grpc_addr,
            cpu_port=args.cpu_port,
            ptfdir=args.ptf_dir,
            port_map_path=args.port_map,
            platform=args.platform,
            generate_tv=args.generate_tv,
            loopback=args.loopback,
            profile=args.profile,
            trex_address=args.trex_address,
            extra_args=unknown_args,
        )

    # clean up TRex
    trex_daemon_client.stop_trex()

    if not success:
        sys.exit(3)


if __name__ == "__main__":
    main()
