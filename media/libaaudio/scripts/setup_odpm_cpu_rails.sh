#!/bin/bash

# Configure ODPM rails to measure CPU specific power.
# See go/odpm-p21-userguide

adb root

# LDO2M(L2M_ALIVE) - DRAM Array Core Power
adb shell 'echo "CH0=LDO2M" > /sys/bus/iio/devices/iio\:device0/enabled_rails'

# These are the defaults.
# BUCK2M(S2M_VDD_CPUCL2):CPU(BIG)
# adb shell 'echo "CH3=BUCK2M" > /sys/bus/iio/devices/iio\:device0/enabled_rails'
# BUCK3M(S3M_VDD_CPUCL1):CPU(MID)
# adb shell 'echo "CH4=BUCK3M" > /sys/bus/iio/devices/iio\:device0/enabled_rails'
# BUCK4M(S4M_VDD_CPUCL0):CPU(LITTLE)
# adb shell 'echo "CH5=BUCK4M" > /sys/bus/iio/devices/iio\:device0/enabled_rails'
# BUCK1M(S1M_VDD_MIF):MIF
# adb shell 'echo "CH7=BUCK1M" > /sys/bus/iio/devices/iio\:device0/enabled_rails'

# These are default on device1.
# BUCK5S(S5S_VDDQ_MEM):DDR
# adb shell 'echo "CH3=BUCK5S" > /sys/bus/iio/devices/iio\:device1/enabled_rails'
# BUCK10S(S10S_VDD2L):DDR
# adb shell 'echo "CH4=BUCK10S" > /sys/bus/iio/devices/iio\:device1/enabled_rails'
# BUCK4S(S4S_VDD2H_MEM):DDR
# adb shell 'echo "CH5=BUCK4S" > /sys/bus/iio/devices/iio\:device1/enabled_rails'

adb shell 'cat /sys/bus/iio/devices/iio\:device0/enabled_rails'
adb shell 'cat /sys/bus/iio/devices/iio\:device1/enabled_rails'

adb unroot

