# Copyright 2020-present Open Networking Foundation
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

from ptf.testutils import group
from ptf.base_tests import BaseTest

@group("spgw")
@group("bng")
@group("dth")
@group("p4rt")
@group("int-dod")
class DummyTest(BaseTest):
    def runTest(self):
        pass
