#!/usr/bin/env python3
# Copyright 2021-present Open Networking Foundation
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
# -*- utf-8 -*-
"""
Generates a snippet of Stratum's chassis_config file with a vendor_config blob for Tofino that
realizes the SD-Fabric slicing/QoS model.

Usage:

    ./gen-stratum-qos-config.py sample-qos-config.yml

Requirements:

    pip3 install pyyaml

"""
import argparse
import os
import sys

import yaml

ptf_common_path = os.path.dirname(os.path.realpath(__file__)) + "/../ptf/tests/common"
sys.path.append(ptf_common_path)

from stratum_qos_config import vendor_config


def main():
    parser = argparse.ArgumentParser(prog="gen-stratum-qos-config.py")
    parser.add_argument("config", help="Path to yaml QoS config file")
    parser.add_argument("-o", "--output", help="output path", default="-")
    args = parser.parse_args()

    yaml_path = args.config
    output_path = args.output
    yaml_config = None
    with open(yaml_path, "r") as stream:
        try:
            yaml_config = yaml.safe_load(stream)
        except yaml.YAMLError as ex:
            print(ex)
            exit(1)

    text = vendor_config(yaml_config)
    if output_path == "-":
        # std output
        print(text)
    else:
        with open(output_path, "w") as output_file:
            output_file.write(text)


if __name__ == "__main__":
    main()
