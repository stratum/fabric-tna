#!/usr/bin/env python2.7
# -*- utf-8 -*-
import argparse
import google.protobuf.text_format as tf
import re
from p4.config.v1 import p4info_pb2

copyright = '''/*
 * Copyright 2020-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
'''

imports = '''
import org.onosproject.net.pi.model.PiActionId;
import org.onosproject.net.pi.model.PiActionParamId;
import org.onosproject.net.pi.model.PiActionProfileId;
import org.onosproject.net.pi.model.PiMeterId;
import org.onosproject.net.pi.model.PiPacketMetadataId;
import org.onosproject.net.pi.model.PiCounterId;
import org.onosproject.net.pi.model.PiMatchFieldId;
import org.onosproject.net.pi.model.PiTableId;'''

PKG_FMT = 'package %s;'
DEFAULT_PKG_PATH = 'org.stratumproject.fabric.tna.%s'

CLASS_OPEN = 'public final class %s {'
CLASS_CLOSE = '}'

DEFAULT_CONSTRUCTOR = '''
    // hide default constructor
    private %s() {
    }
'''

CONST_FMT = '    public static final %s %s = %s;'
SHORT_CONST_FMT = '''    public static final %s %s =
            %s;'''
JAVA_STR = 'String'
EMPTY_STR = ''
JAVA_DOC_FMT = '''/**
 * P4Info constants.
 */'''

PI_HF_FIELD_ID = 'PiMatchFieldId'
PI_HF_FIELD_ID_CST = 'PiMatchFieldId.of("%s")'

PI_TBL_ID = 'PiTableId'
PI_TBL_ID_CST = 'PiTableId.of("%s")'

PI_CTR_ID = 'PiCounterId'
PI_CTR_ID_CST = 'PiCounterId.of("%s")'

PI_ACT_ID = 'PiActionId'
PI_ACT_ID_CST = 'PiActionId.of("%s")'

PI_ACT_PRM_ID = 'PiActionParamId'
PI_ACT_PRM_ID_CST = 'PiActionParamId.of("%s")'

PI_ACT_PROF_ID = 'PiActionProfileId'
PI_ACT_PROF_ID_CST = 'PiActionProfileId.of("%s")'

PI_PKT_META_ID = 'PiPacketMetadataId'
PI_PKT_META_ID_CST = 'PiPacketMetadataId.of("%s")'

PI_METER_ID = 'PiMeterId'
PI_METER_ID_CST = 'PiMeterId.of("%s")'

HF_VAR_PREFIX = 'HDR_'


class ConstantClassGenerator(object):
    headers = set()
    header_fields = set()
    tables = set()
    counters = set()
    direct_counters = set()
    actions = set()
    action_params = set()
    action_profiles = set()
    packet_metadata = set()
    meters = set()

    # https://stackoverflow.com/questions/1175208/elegant-python-function-to-convert-camelcase-to-snake-case
    def convert_camel_to_all_caps(self, name):
        s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
        s1 = re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).upper()
        return s1.replace('.', '_')

    def __init__(self, base_name, pkg_path):

        self.class_name = base_name.title() + 'Constants'
        self.package_name = PKG_FMT % (pkg_path,)
        self.java_doc = JAVA_DOC_FMT

    def parse(self, p4info):
        for tbl in p4info.tables:
            for mf in tbl.match_fields:
                self.header_fields.add(mf.name)

            self.tables.add(tbl.preamble.name)

        for ctr in p4info.counters:
            self.counters.add(ctr.preamble.name)

        for dir_ctr in p4info.direct_counters:
            self.direct_counters.add(dir_ctr.preamble.name)

        for act in p4info.actions:
            self.actions.add(act.preamble.name)

            for param in act.params:
                self.action_params.add(param.name)

        for act_prof in p4info.action_profiles:
            self.action_profiles.add(act_prof.preamble.name)

        for cpm in p4info.controller_packet_metadata:
            for mta in cpm.metadata:
                self.packet_metadata.add(mta.name)
        for mtr in p4info.meters:
            self.meters.add(mtr.preamble.name)

    def const_line(self, name, type, constructor):
        var_name = self.convert_camel_to_all_caps(name)
        if type == PI_HF_FIELD_ID:
            var_name = HF_VAR_PREFIX + var_name
        val = constructor % (name,)

        line = CONST_FMT % (type, var_name, val)
        if len(line) > 80:
            line = SHORT_CONST_FMT % (type, var_name, val)
        return line

    def generate_java(self):
        lines = list()
        lines.append(copyright)
        lines.append(self.package_name)
        lines.append(imports)
        lines.append(self.java_doc)
        # generate the class
        lines.append(CLASS_OPEN % (self.class_name,))
        lines.append(DEFAULT_CONSTRUCTOR % (self.class_name,))

        if len(self.header_fields) is not 0:
            lines.append('    // Header field IDs')
        for hf in self.header_fields:
            lines.append(
                self.const_line(hf, PI_HF_FIELD_ID, PI_HF_FIELD_ID_CST))

        if len(self.tables) is not 0:
            lines.append('    // Table IDs')
        for tbl in self.tables:
            lines.append(self.const_line(tbl, PI_TBL_ID, PI_TBL_ID_CST))

        if len(self.counters) is not 0:
            lines.append('    // Indirect Counter IDs')
        for ctr in self.counters:
            lines.append(self.const_line(ctr, PI_CTR_ID, PI_CTR_ID_CST))

        if len(self.direct_counters) is not 0:
            lines.append('    // Direct Counter IDs')
        for dctr in self.direct_counters:
            lines.append(self.const_line(dctr, PI_CTR_ID, PI_CTR_ID_CST))

        if len(self.actions) is not 0:
            lines.append('    // Action IDs')
        for act in self.actions:
            lines.append(self.const_line(act, PI_ACT_ID, PI_ACT_ID_CST))

        if len(self.action_params) is not 0:
            lines.append('    // Action Param IDs')
        for act_prm in self.action_params:
            lines.append(
                self.const_line(act_prm, PI_ACT_PRM_ID, PI_ACT_PRM_ID_CST))

        if len(self.action_profiles) is not 0:
            lines.append('    // Action Profile IDs')
        for act_prof in self.action_profiles:
            lines.append(
                self.const_line(act_prof, PI_ACT_PROF_ID, PI_ACT_PROF_ID_CST))

        if len(self.packet_metadata) is not 0:
            lines.append('    // Packet Metadata IDs')
        for pmeta in self.packet_metadata:
            if not pmeta.startswith("_"):
                lines.append(
                    self.const_line(pmeta, PI_PKT_META_ID, PI_PKT_META_ID_CST))

        if len(self.meters) is not 0:
            lines.append('    // Meter IDs')
        for mtr in self.meters:
            lines.append(self.const_line(mtr, PI_METER_ID, PI_METER_ID_CST))
        lines.append(CLASS_CLOSE)
        # end of class

        return '\n'.join(lines)


def gen_pkg_path(output, base_name):
    if output is not None:
        i = output.find('java/')
        if i != -1:
            pkg_path = output[i + 5:]
            last_slash = pkg_path.rfind('/')
            pkg_path = pkg_path[:last_slash].replace('/', '.')
            return pkg_path
    return DEFAULT_PKG_PATH % (base_name,)


def main():
    parser = argparse.ArgumentParser(prog='gen-p4-constants.py',
                                     description='P4Info to Java constant generator.')
    parser.add_argument('name',
                        help='Name of the constant, will be used as class name')
    parser.add_argument('p4info', help='P4Info file')
    parser.add_argument('-o', '--output', help='output path', default='-')
    parser.add_argument('--with-package-path',
                        help='Specify the java package path', dest='pkg_path')
    args = parser.parse_args()

    base_name = args.name
    file_name = args.p4info
    output = args.output
    pkg_path = args.pkg_path
    if pkg_path is None:
        pkg_path = gen_pkg_path(output, base_name)
    p4info = p4info_pb2.P4Info()
    with open(file_name, 'r') as intput_file:
        s = intput_file.read()
        tf.Merge(s, p4info)

    gen = ConstantClassGenerator(base_name, pkg_path)
    gen.parse(p4info)

    java_code = gen.generate_java()

    if output == '-':
        # std output
        print java_code
    else:
        with open(output, 'w') as output_file:
            output_file.write(java_code)


if __name__ == '__main__':
    main()
