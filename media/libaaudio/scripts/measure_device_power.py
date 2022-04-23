#!/usr/bin/python3
"""
 * Copyright (C) 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
"""

'''
Measure CPU related power on Pixel 6 or later devices using ODPM,
the On Device Power Measurement tool.
Generate a CSV report for putting in a spreadsheet
'''

import argparse
import os
import re
import subprocess
import sys
import time

# defaults
PRE_DELAY_SECONDS = 0.5 # time to sleep before command to avoid adb unroot error
DEFAULT_NUM_ITERATIONS = 5
DEFAULT_FILE_NAME = 'energy_commands.txt'

'''
Default rail assignments
philburk-macbookpro3:expt philburk$ adb shell cat /sys/bus/iio/devices/iio\:device0/energy_value
t=349894
CH0(T=349894)[S10M_VDD_TPU], 5578756
CH1(T=349894)[VSYS_PWR_MODEM], 29110940
CH2(T=349894)[VSYS_PWR_RFFE], 3166046
CH3(T=349894)[S2M_VDD_CPUCL2], 30203502
CH4(T=349894)[S3M_VDD_CPUCL1], 23377533
CH5(T=349894)[S4M_VDD_CPUCL0], 46356942
CH6(T=349894)[S5M_VDD_INT], 10771876
CH7(T=349894)[S1M_VDD_MIF], 21091363
philburk-macbookpro3:expt philburk$ adb shell cat /sys/bus/iio/devices/iio\:device1/energy_value
t=359458
CH0(T=359458)[VSYS_PWR_WLAN_BT], 45993209
CH1(T=359458)[L2S_VDD_AOC_RET], 2822928
CH2(T=359458)[S9S_VDD_AOC], 6923706
CH3(T=359458)[S5S_VDDQ_MEM], 4658202
CH4(T=359458)[S10S_VDD2L], 5506273
CH5(T=359458)[S4S_VDD2H_MEM], 14254574
CH6(T=359458)[S2S_VDD_G3D], 5315420
CH7(T=359458)[VSYS_PWR_DISPLAY], 81221665
'''

'''
LDO2M(L2M_ALIVE):DDR  -> DRAM Array Core Power
BUCK4S(S4S_VDD2H_MEM):DDR -> Normal operation data and control path logic circuits
BUCK5S(S5S_VDDQ_MEM):DDR -> LPDDR I/O interface
BUCK10S(S10S_VDD2L):DDR  -> DVFSC (1600Mbps or lower) operation data and control path logic circuits
BUCK1M (S1M_VDD_MIF):  SoC side Memory InterFace and Controller
'''

# Map between rail name and human readable name.
ENERGY_DICTIONARY = { \
        'S4M_VDD_CPUCL0': 'CPU0', \
        'S3M_VDD_CPUCL1': 'CPU1', \
        'S2M_VDD_CPUCL2': 'CPU2', \
        'S1M_VDD_MIF': 'MIF', \
        'L2M_ALIVE': 'DDRAC', \
        'S4S_VDD2H_MEM': 'DDRNO', \
        'S10S_VDD2L': 'DDR16', \
        'S5S_VDDQ_MEM': 'DDRIO', \
        'VSYS_PWR_DISPLAY': 'SCREEN'}

SORTED_ENERGY_LIST = sorted(ENERGY_DICTIONARY, key=ENERGY_DICTIONARY.get)

# Sometimes adb returns 1 for no apparent reason.
# So try several times.
# @return 0 on success
def adbTryMultiple(command):
    returnCode = 1
    count = 0
    limit = 5
    while count < limit and returnCode != 0:
        print(('Try to adb {} {} of {}'.format(command, count, limit)))
        subprocess.call(["adb", "wait-for-device"])
        time.sleep(PRE_DELAY_SECONDS)
        returnCode = subprocess.call(["adb", command])
        print(('returnCode = {}'.format(returnCode)))
        count += 1
    return returnCode

# Sometimes "adb root" returns 1!
# So try several times.
# @return 0 on success
def adbRoot():
    return adbTryMultiple("root");

# Sometimes "adb unroot" returns 1!
# So try several times.
# @return 0 on success
def adbUnroot():
    return adbTryMultiple("unroot");

# @param commandString String containing shell command
# @return Both the stdout and stderr of the commands run
def runCommand(commandString):
    print(commandString)
    if commandString == "adb unroot":
        result = adbUnroot()
    elif commandString == "adb root":
        result = adbRoot()
    else:
        commandArray = commandString.split(' ')
        result = subprocess.run(commandArray, check=True, capture_output=True).stdout
    return result

# @param commandString String containing ADB command
# @return Both the stdout and stderr of the commands run
def adbCommand(commandString):
    if commandString == "unroot":
        result = adbUnroot()
    elif commandString == "root":
        result = adbRoot()
    else:
        print(("adb " + commandString))
        commandArray = ["adb"] + commandString.split(' ')
        subprocess.call(["adb", "wait-for-device"])
        result = subprocess.run(commandArray, check=True, capture_output=True).stdout
    return result

# Parse a line that looks like "CH3(T=10697635)[S2M_VDD_CPUCL2], 116655335"
# Use S2M_VDD_CPUCL2 as the tag and set value to the number
# in the report dictionary.
def parseEnergyValue(string):
    return tuple(re.split('\[|\], +', string)[1:])

# Read accumulated energy into a dictionary.
def measureEnergyForDevice(deviceIndex, report):
    # print("measureEnergyForDevice " + str(deviceIndex))
    tableBytes = adbCommand( \
            'shell cat /sys/bus/iio/devices/iio\:device{}/energy_value'\
            .format(deviceIndex))
    table = tableBytes.decode("utf-8")
    # print(table)
    for count, line in enumerate(table.splitlines()):
        if count > 0:
            tagEnergy = parseEnergyValue(line)
            report[tagEnergy[0]] = int(tagEnergy[1].strip())
    # print(report)

def measureEnergyOnce():
    adbCommand("root")
    report = {}
    d0 = measureEnergyForDevice(0, report)
    d1 = measureEnergyForDevice(1, report)
    adbUnroot()
    return report

# Subtract numeric values for matching keys.
def subtractReports(A, B):
    return {x: A[x] - B[x] for x in A if x in B}

# Add numeric values for matching keys.
def addReports(A, B):
    return {x: A[x] + B[x] for x in A if x in B}

# Divide numeric values by divisor.
# @return Modified copy of report.
def divideReport(report, divisor):
    return {key: val / divisor for key, val in list(report.items())}

# Generate a dictionary that is the difference between two measurements over time.
def measureEnergyOverTime(duration):
    report1 = measureEnergyOnce()
    print(("Measure energy for " + str(duration) + " seconds."))
    time.sleep(duration)
    report2 = measureEnergyOnce()
    return subtractReports(report2, report1)

# Generate a CSV string containing the human readable headers.
def formatEnergyHeader():
    header = ""
    for tag in SORTED_ENERGY_LIST:
        header += ENERGY_DICTIONARY[tag] + ", "
    return header

# Generate a CSV string containing the numeric values.
def formatEnergyData(report):
    data = ""
    for tag in SORTED_ENERGY_LIST:
        if tag in list(report.keys()):
            data += str(report[tag]) + ", "
        else:
            data += "-1,"
    return data

def printEnergyReport(report):
    s = "\n"
    s += "Values are in microWattSeconds\n"
    s += "Report below is CSV format for pasting into a spreadsheet:\n"
    s += formatEnergyHeader() + "\n"
    s += formatEnergyData(report) + "\n"
    print(s)

# Generate a dictionary that is the difference between two measurements
# before and after executing the command.
def measureEnergyForCommand(command):
    report1 = measureEnergyOnce()
    print(("Measure energy for:  " + command))
    result = runCommand(command)
    report2 = measureEnergyOnce()
    # print(result)
    return subtractReports(report2, report1)

# Average the results of several measurements for one command.
def averageEnergyForCommand(command, count):
    print("=================== #0\n")
    sumReport = measureEnergyForCommand(command)
    for i in range(1, count):
        print(("=================== #" + str(i) + "\n"))
        report = measureEnergyForCommand(command)
        sumReport = addReports(sumReport, report)
    print(sumReport)
    return divideReport(sumReport, count)

# Parse a list of commands in a file.
# Lines ending in "\" are continuation lines.
# Lines beginning with "#" are comments.
def measureEnergyForCommands(fileName):
    finalReport = "------------------------------------\n"
    finalReport += "comment, command, " + formatEnergyHeader() + "\n"
    comment = ""
    try:
        fp = open(fileName)
        line = fp.readline()
        while line:
            command = line.strip()
            if command.startswith("#"):
                # ignore comment
                print((command + "\n"))
                comment = command[1:].strip() # remove leading '#'
            elif command.endswith('\\'):
                command = command[:-1].strip() # remove trailing '\'
                runCommand(command)
            elif command:
                report = averageEnergyForCommand(command, DEFAULT_NUM_ITERATIONS)
                finalReport += comment + ", " + command + ", " + formatEnergyData(report) + "\n"
                print(finalReport)
            line = fp.readline()
    finally:
        fp.close()
    return finalReport

def main():
    # parse command line args
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--seconds',
            help="Measure power for N seconds. Ignore scriptFile.",
            type=float)
    parser.add_argument("fileName",
            nargs = '?',
            help="Path to file containing commands to be measured."
                    + " Default path = " + DEFAULT_FILE_NAME + "."
                    + " Lines ending in '\' are continuation lines."
                    + " Lines beginning with '#' are comments.",
                    default=DEFAULT_FILE_NAME)
    args=parser.parse_args();

    print(("seconds  = " + str(args.seconds)))
    print(("fileName = " + str(args.fileName)))
    # Process command line
    if args.seconds:
        report = measureEnergyOverTime(args.seconds)
        printEnergyReport(report)
    else:
        report = measureEnergyForCommands(args.fileName)
        print(report)
    print("Finished.\n")
    return 0

if __name__ == '__main__':
    sys.exit(main())
