#!/bin/bash
#
# Script to run all transcoding related tests from subfolders.
# Run script from this folder.
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
SYNC_FINISHED=true

# Run the transcoding service tests.
pushd tests
. build_and_run_all_unit_tests.sh
popd

# Run the transcoder tests.
pushd transcoder/tests/
. build_and_run_all_unit_tests.sh
popd

