#!/usr/bin/python3

#
# Copyright 2018, The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import argparse
import re
import sys
import os
import logging
import xml.etree.ElementTree as ET
import xml.etree.ElementInclude as EI
import xml.dom.minidom as MINIDOM
from collections import OrderedDict

#
# Helper script that helps to feed at build time the XML criterion types file used by
# the engineconfigurable to start the parameter-framework.
# It prevents to fill them manually and avoid divergences with android.
#
# The Device Types criterion types are fed from audio-base.h file with the option
#           --androidaudiobaseheader <path/to/android/audio/base/file/audio-base.h>
#
# The Device Addresses criterion types are fed from the audio policy configuration file
# in order to discover all the devices for which the address matter.
#           --audiopolicyconfigurationfile <path/to/audio_policy_configuration.xml>
#
# The reference file of criterion types must also be set as an input of the script:
#           --criteriontypes <path/to/criterion/file/audio_criterion_types.xml.in>
#
# At last, the output of the script shall be set also:
#           --outputfile <path/to/out/vendor/etc/audio_criterion_types.xml>
#

def parseArgs():
    argparser = argparse.ArgumentParser(description="Parameter-Framework XML \
                                        audio criterion type file generator.\n\
                                        Exit with the number of (recoverable or not) \
                                        error that occured.")
    argparser.add_argument('--androidaudiobaseheader',
                           help="Android Audio Base C header file, Mandatory.",
                           metavar="ANDROID_AUDIO_BASE_HEADER",
                           type=argparse.FileType('r'),
                           required=True)
    argparser.add_argument('--androidaudiocommonbaseheader',
                           help="Android Audio CommonBase C header file, Mandatory.",
                           metavar="ANDROID_AUDIO_COMMON_BASE_HEADER",
                           type=argparse.FileType('r'),
                           required=True)
    argparser.add_argument('--audiopolicyconfigurationfile',
                           help="Android Audio Policy Configuration file, Mandatory.",
                           metavar="(AUDIO_POLICY_CONFIGURATION_FILE)",
                           type=argparse.FileType('r'),
                           required=True)
    argparser.add_argument('--criteriontypes',
                           help="Criterion types XML base file, in \
                           '<criterion_types> \
                               <criterion_type name="" type=<inclusive|exclusive> \
                               values=<value1,value2,...>/>' \
                           format. Mandatory.",
                           metavar="CRITERION_TYPE_FILE",
                           type=argparse.FileType('r'),
                           required=True)
    argparser.add_argument('--outputfile',
                           help="Criterion types outputfile file. Mandatory.",
                           metavar="CRITERION_TYPE_OUTPUT_FILE",
                           type=argparse.FileType('w'),
                           required=True)
    argparser.add_argument('--verbose',
                           action='store_true')

    return argparser.parse_args()


def generateXmlCriterionTypesFile(criterionTypes, addressCriteria, criterionTypesFile, outputFile):

    logging.info("Importing criterionTypesFile {}".format(criterionTypesFile))
    criterion_types_in_tree = ET.parse(criterionTypesFile)

    criterion_types_root = criterion_types_in_tree.getroot()

    for criterion_name, values_dict in criterionTypes.items():
        for criterion_type in criterion_types_root.findall('criterion_type'):
            if criterion_type.get('name') == criterion_name:
                values_node = ET.SubElement(criterion_type, "values")
                ordered_values = OrderedDict(sorted(values_dict.items(), key=lambda x: x[1]))
                for key, value in ordered_values.items():
                    value_node = ET.SubElement(values_node, "value")
                    value_node.set('numerical', str(value))
                    value_node.set('literal', key)

    if addressCriteria:
        for criterion_name, values_list in addressCriteria.items():
            for criterion_type in criterion_types_root.findall('criterion_type'):
                if criterion_type.get('name') == criterion_name:
                    index = 0
                    existing_values_node = criterion_type.find("values")
                    if existing_values_node is not None:
                        for existing_value in existing_values_node.findall('value'):
                            if existing_value.get('numerical') == str(1 << index):
                                index += 1
                        values_node = existing_values_node
                    else:
                        values_node = ET.SubElement(criterion_type, "values")

                    for value in values_list:
                        value_node = ET.SubElement(values_node, "value", literal=value)
                        value_node.set('numerical', str(1 << index))
                        index += 1

    xmlstr = ET.tostring(criterion_types_root, encoding='utf8', method='xml')
    reparsed = MINIDOM.parseString(xmlstr)
    prettyXmlStr = reparsed.toprettyxml(newl='\r\n')
    prettyXmlStr = os.linesep.join([s for s in prettyXmlStr.splitlines() if s.strip()])
    outputFile.write(prettyXmlStr)

def capitalizeLine(line):
    return ' '.join((w.capitalize() for w in line.split(' ')))


#
# Parse the audio policy configuration file and output a dictionary of device criteria addresses
#
def parseAndroidAudioPolicyConfigurationFile(audiopolicyconfigurationfile):

    logging.info("Checking Audio Policy Configuration file {}".format(audiopolicyconfigurationfile))
    #
    # extract all devices addresses from audio policy configuration file
    #
    address_criteria_mapping_table = {
        'sink' : "OutputDevicesAddressesType",
        'source' : "InputDevicesAddressesType"}

    address_criteria = {
        'OutputDevicesAddressesType' : [],
        'InputDevicesAddressesType' : []}

    old_working_dir = os.getcwd()
    print("Current working directory %s" % old_working_dir)

    new_dir = os.path.join(old_working_dir, audiopolicyconfigurationfile.name)

    policy_in_tree = ET.parse(audiopolicyconfigurationfile)
    os.chdir(os.path.dirname(os.path.normpath(new_dir)))

    print("new working directory %s" % os.getcwd())

    policy_root = policy_in_tree.getroot()
    EI.include(policy_root)

    os.chdir(old_working_dir)

    for device in policy_root.iter('devicePort'):
        for key in address_criteria_mapping_table.keys():
            if device.get('role') == key and device.get('address'):
                logging.info("{}: <{}>".format(key, device.get('address')))
                address_criteria[address_criteria_mapping_table[key]].append(device.get('address'))

    for criteria in address_criteria:
        values = ','.join(address_criteria[criteria])
        logging.info("{}: <{}>".format(criteria, values))

    return address_criteria

#
# Parse the audio-base.h file and output a dictionary of android dependent criterion types:
#   -Android Mode
#   -Output devices type
#   -Input devices type
#
def parseAndroidAudioFile(androidaudiobaseheaderFile, androidaudiocommonbaseheaderFile):
    #
    # Adaptation table between Android Enumeration prefix and Audio PFW Criterion type names
    #
    criterion_mapping_table = {
        'HAL_AUDIO_MODE' : "AndroidModeType",
        'AUDIO_DEVICE_OUT' : "OutputDevicesMaskType",
        'AUDIO_DEVICE_IN' : "InputDevicesMaskType"}

    all_criteria = {
        'AndroidModeType' : {},
        'OutputDevicesMaskType' : {},
        'InputDevicesMaskType' : {}}

    #
    # _CNT, _MAX, _ALL and _NONE are prohibited values as ther are just helpers for enum users.
    #
    ignored_values = ['CNT', 'MAX', 'ALL', 'NONE']

    #
    # Reaching 32 bit limit for inclusive criterion out devices: removing
    #
    ignored_output_device_values = ['BleSpeaker', 'BleHeadset']

    criteria_pattern = re.compile(
        r"\s*V\((?P<type>(?:"+'|'.join(criterion_mapping_table.keys()) + "))_" \
        r"(?P<literal>(?!" + '|'.join(ignored_values) + ")\w*)\s*,\s*" \
        r"(?:AUDIO_DEVICE_BIT_IN \| )?(?P<values>(?:0[xX])?[0-9a-fA-F]+|[0-9]+)")

    logging.info("Checking Android Header file {}".format(androidaudiobaseheaderFile))

    for line_number, line in enumerate(androidaudiobaseheaderFile):
        match = criteria_pattern.match(line)
        if match:
            logging.debug("The following line is VALID: {}:{}\n{}".format(
                androidaudiobaseheaderFile.name, line_number, line))

            criterion_name = criterion_mapping_table[match.groupdict()['type']]
            criterion_literal = \
                ''.join((w.capitalize() for w in match.groupdict()['literal'].split('_')))
            criterion_numerical_value = match.groupdict()['values']

            # for AUDIO_DEVICE_IN: need to remove sign bit / rename default to stub
            if criterion_name == "InputDevicesMaskType":
                if criterion_literal == "Default":
                    criterion_numerical_value = str(int("0x40000000", 0))
                else:
                    try:
                        string_int = int(criterion_numerical_value, 0)
                    except ValueError:
                        # Handle the exception
                        logging.info("value {}:{} for criterion {} is not a number, ignoring"
                            .format(criterion_numerical_value, criterion_literal, criterion_name))
                        continue
                    criterion_numerical_value = str(int(criterion_numerical_value, 0) & ~2147483648)

            if criterion_name == "OutputDevicesMaskType":
                if criterion_literal == "Default":
                    criterion_numerical_value = str(int("0x40000000", 0))
                if criterion_literal in ignored_output_device_values:
                    logging.info("OutputDevicesMaskType skipping {}".format(criterion_literal))
                    continue
            try:
                string_int = int(criterion_numerical_value, 0)
            except ValueError:
                # Handle the exception
                logging.info("The value {}:{} is for criterion {} is not a number, ignoring"
                    .format(criterion_numerical_value, criterion_literal, criterion_name))
                continue

            # Remove duplicated numerical values
            if int(criterion_numerical_value, 0) in all_criteria[criterion_name].values():
                logging.info("criterion {} duplicated values:".format(criterion_name))
                logging.info("{}:{}".format(criterion_numerical_value, criterion_literal))
                logging.info("KEEPING LATEST")
                for key in list(all_criteria[criterion_name]):
                    if all_criteria[criterion_name][key] == int(criterion_numerical_value, 0):
                        del all_criteria[criterion_name][key]

            all_criteria[criterion_name][criterion_literal] = int(criterion_numerical_value, 0)

            logging.debug("type:{},".format(criterion_name))
            logging.debug("iteral:{},".format(criterion_literal))
            logging.debug("values:{}.".format(criterion_numerical_value))

    logging.info("Checking Android Common Header file {}".format(androidaudiocommonbaseheaderFile))

    criteria_pattern = re.compile(
        r"\s*(?P<type>(?:"+'|'.join(criterion_mapping_table.keys()) + "))_" \
        r"(?P<literal>(?!" + '|'.join(ignored_values) + ")\w*)\s*=\s*" \
        r"(?:AUDIO_DEVICE_BIT_IN \| )?(?P<values>(?:0[xX])?[0-9a-fA-F]+|[0-9]+)")

    for line_number, line in enumerate(androidaudiocommonbaseheaderFile):
        match = criteria_pattern.match(line)
        if match:
            logging.debug("The following line is VALID: {}:{}\n{}".format(
                androidaudiocommonbaseheaderFile.name, line_number, line))

            criterion_name = criterion_mapping_table[match.groupdict()['type']]
            criterion_literal = \
                ''.join((w.capitalize() for w in match.groupdict()['literal'].split('_')))
            criterion_numerical_value = match.groupdict()['values']

            try:
                string_int = int(criterion_numerical_value, 0)
            except ValueError:
                # Handle the exception
                logging.info("The value {}:{} is for criterion {} is not a number, ignoring"
                    .format(criterion_numerical_value, criterion_literal, criterion_name))
                continue

            # Remove duplicated numerical values
            if int(criterion_numerical_value, 0) in all_criteria[criterion_name].values():
                logging.info("criterion {} duplicated values:".format(criterion_name))
                logging.info("{}:{}".format(criterion_numerical_value, criterion_literal))
                logging.info("KEEPING LATEST")
                for key in list(all_criteria[criterion_name]):
                    if all_criteria[criterion_name][key] == int(criterion_numerical_value, 0):
                        del all_criteria[criterion_name][key]

            all_criteria[criterion_name][criterion_literal] = int(criterion_numerical_value, 0)

            logging.debug("type:{},".format(criterion_name))
            logging.debug("iteral:{},".format(criterion_literal))
            logging.debug("values:{}.".format(criterion_numerical_value))

    return all_criteria


def main():
    logging.root.setLevel(logging.INFO)
    args = parseArgs()

    all_criteria = parseAndroidAudioFile(args.androidaudiobaseheader,
                                         args.androidaudiocommonbaseheader)

    address_criteria = parseAndroidAudioPolicyConfigurationFile(args.audiopolicyconfigurationfile)

    criterion_types = args.criteriontypes

    generateXmlCriterionTypesFile(all_criteria, address_criteria, criterion_types, args.outputfile)

# If this file is directly executed
if __name__ == "__main__":
    sys.exit(main())
