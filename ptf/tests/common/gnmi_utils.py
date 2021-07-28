# Copyright 2021-present Open Networking Foundation
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

import time

from base_test import *
from gnmi import gnmi_pb2, gnmi_pb2_grpc

# This file contains utility functions that make it easy to perform gNMI
# requests against the switch under test.

_grpc_addr = testutils.test_param_get("grpcaddr")


def _parse_key_val(key_val_str):
    # [key1=val1,key2=val2,.....]
    key_val_str = key_val_str[1:-1]  # remove "[]"
    return [kv.split("=") for kv in key_val_str.split(",")]


# parse path_str string and add elements to path (gNMI Path class)
def _build_path(path_str, path):
    if path_str == "/":
        # the root path should be an empty path
        return

    path_elem_info_list = re.findall(r"/([^/\[]+)(\[([^=]+=[^\]]+)\])?", path_str)

    for path_elem_info in path_elem_info_list:
        # [('interfaces', ''), ('interface', '[name=1/1/1]'), ...]
        pe = path.elem.add()
        pe.name = path_elem_info[0]

        if path_elem_info[1]:
            for kv in _parse_key_val(path_elem_info[1]):
                # [('name', '1/1/1'), ...]
                pe.key[kv[0]] = kv[1]


# Public API starts here.


def build_gnmi_get_req(path: str):
    req = gnmi_pb2.GetRequest()
    req.encoding = gnmi_pb2.PROTO
    p = req.path.add()
    _build_path(path, p)
    if path == "/":
        # Special case
        req.type = gnmi_pb2.GetRequest.CONFIG
    return req


def build_gnmi_set_req(path: str, value, replace=False):
    req = gnmi_pb2.SetRequest()
    if replace:
        update = req.replace.add()
    else:
        update = req.update.add()
    _build_path(path, update.path)
    if type(value) is bool:
        update.val.bool_val = value
    elif type(value) is str:
        update.val.string_val = value
    elif type(value) is bytes:
        update.val.bytes_val = value
    elif type(value) is int:
        update.val.int_val = value
    elif type(value) is float:
        update.val.float_val = value
    else:
        raise ValueError("Unknown value type %s." % type(value))

    return req


def do_get(req):
    channel = grpc.insecure_channel(_grpc_addr)
    stub = gnmi_pb2_grpc.gNMIStub(channel)
    resp = stub.Get(req)
    return resp


def do_set(req):
    channel = grpc.insecure_channel(_grpc_addr)
    stub = gnmi_pb2_grpc.gNMIStub(channel)
    resp = stub.Set(req)
    return resp


def push_chassis_config(config: bytes):
    req = build_gnmi_set_req("/", config, True)
    do_set(req)
    # TODO(max): most tests assume all ports are up and ready, but this might
    # not be the case as port setup can take a few seconds. For now we remedy
    # this by waiting a bit, but in the future we should check the port state
    # via gNMI.
    time.sleep(2)
