# Copyright 2020-present Open Networking Foundation
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

import xnt
import sys

if len(sys.argv) > 2:
    results = xnt.analyze_report_pcap(str(sys.argv[1]), int(sys.argv[2]))
else:
    results = xnt.analyze_report_pcap(str(sys.argv[1]))
