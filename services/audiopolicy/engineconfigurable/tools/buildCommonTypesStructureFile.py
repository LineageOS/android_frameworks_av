#! /usr/bin/python3
#
# pylint: disable=line-too-long, missing-docstring, logging-format-interpolation, invalid-name

#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse
import re
import sys
import os
import logging
import xml.etree.ElementTree as ET
from collections import OrderedDict
import xml.dom.minidom as MINIDOM

def parseArgs():
    argparser = argparse.ArgumentParser(description="Parameter-Framework XML \
        structure file generator.\n\
        Exit with the number of (recoverable or not) error that occured.")
    argparser.add_argument('--androidaudiobaseheader',
                           help="Android Audio Base C header file, Mandatory.",
                           metavar="ANDROID_AUDIO_BASE_HEADER",
                           type=argparse.FileType('r'),
                           required=True)
    argparser.add_argument('--commontypesstructure',
                           help="Structure XML base file. Mandatory.",
                           metavar="STRUCTURE_FILE_IN",
                           type=argparse.FileType('r'),
                           required=True)
    argparser.add_argument('--outputfile',
                           help="Structure XML file. Mandatory.",
                           metavar="STRUCTURE_FILE_OUT",
                           type=argparse.FileType('w'),
                           required=True)
    argparser.add_argument('--verbose',
                           action='store_true')

    return argparser.parse_args()


def findBitPos(decimal):
    pos = 0
    i = 1
    while i != decimal:
        i = i << 1
        pos = pos + 1
        if pos == 32:
            return -1
    return pos


def generateXmlStructureFile(componentTypeDict, structureTypesFile, outputFile):

    logging.info("Importing structureTypesFile {}".format(structureTypesFile))
    component_types_in_tree = ET.parse(structureTypesFile)

    component_types_root = component_types_in_tree.getroot()

    for component_types_name, values_dict in componentTypeDict.items():
        for component_type in component_types_root.findall('ComponentType'):
            if component_type.get('Name') == component_types_name:
                bitparameters_node = component_type.find("BitParameterBlock")
                if bitparameters_node is not None:
                    ordered_values = OrderedDict(sorted(values_dict.items(), key=lambda x: x[1]))
                    for key, value in ordered_values.items():
                        value_node = ET.SubElement(bitparameters_node, "BitParameter")
                        value_node.set('Name', key)
                        value_node.set('Size', "1")
                        value_node.set('Pos', str(findBitPos(value)))

                enum_parameter_node = component_type.find("EnumParameter")
                if enum_parameter_node is not None:
                    ordered_values = OrderedDict(sorted(values_dict.items(), key=lambda x: x[1]))
                    for key, value in ordered_values.items():
                        value_node = ET.SubElement(enum_parameter_node, "ValuePair")
                        value_node.set('Literal', key)
                        value_node.set('Numerical', str(value))

    xmlstr = ET.tostring(component_types_root, encoding='utf8', method='xml')
    reparsed = MINIDOM.parseString(xmlstr)
    prettyXmlStr = reparsed.toprettyxml(indent="    ", newl='\n')
    prettyXmlStr = os.linesep.join([s for s in prettyXmlStr.splitlines() if s.strip()])
    outputFile.write(prettyXmlStr)


def capitalizeLine(line):
    return ' '.join((w.capitalize() for w in line.split(' ')))

def parseAndroidAudioFile(androidaudiobaseheaderFile):
    #
    # Adaptation table between Android Enumeration prefix and Audio PFW Criterion type names
    #
    component_type_mapping_table = {
        'AUDIO_STREAM' : "VolumeProfileType",
        'AUDIO_DEVICE_OUT' : "OutputDevicesMask",
        'AUDIO_DEVICE_IN' : "InputDevicesMask"}

    all_component_types = {
        'VolumeProfileType' : {},
        'OutputDevicesMask' : {},
        'InputDevicesMask' : {}
    }

    #
    # _CNT, _MAX, _ALL and _NONE are prohibited values as ther are just helpers for enum users.
    #
    ignored_values = ['CNT', 'MAX', 'ALL', 'NONE']

    criteria_pattern = re.compile(
        r"\s*(?P<type>(?:"+'|'.join(component_type_mapping_table.keys()) + "))_" \
        r"(?P<literal>(?!" + '|'.join(ignored_values) + ")\w*)\s*=\s*" \
        r"(?P<values>(?:0[xX])?[0-9a-fA-F]+)")

    logging.info("Checking Android Header file {}".format(androidaudiobaseheaderFile))

    for line_number, line in enumerate(androidaudiobaseheaderFile):
        match = criteria_pattern.match(line)
        if match:
            logging.debug("The following line is VALID: {}:{}\n{}".format(
                androidaudiobaseheaderFile.name, line_number, line))

            component_type_name = component_type_mapping_table[match.groupdict()['type']]
            component_type_literal = match.groupdict()['literal'].lower()

            component_type_numerical_value = match.groupdict()['values']

            # for AUDIO_DEVICE_IN: need to remove sign bit / rename default to stub
            if component_type_name == "InputDevicesMask":
                component_type_numerical_value = str(int(component_type_numerical_value, 0) & ~2147483648)
                if component_type_literal == "default":
                    component_type_literal = "stub"

            if component_type_name == "OutputDevicesMask":
                if component_type_literal == "default":
                    component_type_literal = "stub"

            # Remove duplicated numerical values
            if int(component_type_numerical_value, 0) in all_component_types[component_type_name].values():
                logging.info("The value {}:{} is duplicated for criterion {}, KEEPING LATEST".format(component_type_numerical_value, component_type_literal, component_type_name))
                for key in list(all_component_types[component_type_name]):
                    if all_component_types[component_type_name][key] == int(component_type_numerical_value, 0):
                        del all_component_types[component_type_name][key]

            all_component_types[component_type_name][component_type_literal] = int(component_type_numerical_value, 0)

            logging.debug("type:{}, literal:{}, values:{}.".format(component_type_name, component_type_literal, component_type_numerical_value))

    # Transform input source in inclusive criterion
    shift = len(all_component_types['OutputDevicesMask'])
    if shift > 32:
        logging.critical("OutputDevicesMask incompatible with criterion representation on 32 bits")
        logging.info("EXIT ON FAILURE")
        exit(1)

    for component_types in all_component_types:
        values = ','.join('{}:{}'.format(value, key) for key, value in all_component_types[component_types].items())
        logging.info("{}: <{}>".format(component_types, values))

    return all_component_types


def main():
    logging.root.setLevel(logging.INFO)
    args = parseArgs()
    route_criteria = 0

    all_component_types = parseAndroidAudioFile(args.androidaudiobaseheader)

    generateXmlStructureFile(all_component_types, args.commontypesstructure, args.outputfile)

# If this file is directly executed
if __name__ == "__main__":
    sys.exit(main())
