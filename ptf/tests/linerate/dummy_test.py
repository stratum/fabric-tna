# Copyright 2020-present Open Networking Foundation
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

from base_test import *
from ptf.testutils import group

@group("spgw")
@group("bng")
@group("dth")
@group("p4rt")
@group("int-dod")
class DummyTest():
    @autocleanup
    def runTest(self):
        pass
