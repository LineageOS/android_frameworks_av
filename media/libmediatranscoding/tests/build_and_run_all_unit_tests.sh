#!/bin/bash
#
# Run tests in this directory.
#

if [ -z "$ANDROID_BUILD_TOP" ]; then
    echo "Android build environment not set"
    exit -1
fi

# ensure we have mm
. $ANDROID_BUILD_TOP/build/envsetup.sh

mm

echo "waiting for device"

adb root && adb wait-for-device remount && adb sync

echo "========================================"

echo "testing TranscodingClientManager"
adb shell /data/nativetest64/TranscodingClientManager_tests/TranscodingClientManager_tests

echo "testing AdjustableMaxPriorityQueue"
adb shell /data/nativetest64/AdjustableMaxPriorityQueue_tests/AdjustableMaxPriorityQueue_tests
