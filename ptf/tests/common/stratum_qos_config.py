#!/usr/bin/env python3
# Copyright 2021-present Open Networking Foundation
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
# -*- utf-8 -*-
"""
Wrapper around util/gen-stratum-qos-config.py that allows calling vendor_config directly from PTF test classes.
"""
import importlib.util
import os

# We cannot import directly gen-stratum-qos-config because module names cannot contain dashes...
config_script_path = (
    os.path.dirname(os.path.realpath(__file__))
    + "/../../../util/gen-stratum-qos-config.py"
)
spec = importlib.util.spec_from_file_location(
    "gen_stratum_qos_config", config_script_path
)
gen_stratum_qos_config = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gen_stratum_qos_config)


def vendor_config(yaml_config):
    return gen_stratum_qos_config.vendor_config(yaml_config)
