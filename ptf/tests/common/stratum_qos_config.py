#!/usr/bin/env python3
# Copyright 2021-present Open Networking Foundation
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
# -*- utf-8 -*-
"""
Wrapper around util/gen-qos-config.py that allows calling vendor_config directly from PTF test classes.
"""
import importlib.util
import os

# We cannot import directly gen-qos-config because module names cannot contain dashes...
config_script_path = (
    os.path.dirname(os.path.realpath(__file__)) + "/../../../util/gen-qos-config.py"
)
spec = importlib.util.spec_from_file_location(
    "gen_qos_config", config_script_path
)
gen_qos_config = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gen_qos_config)


def vendor_config(yaml_config):
    return gen_qos_config.text_config(yaml_config, type="stratum")
