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

echo "[==========] installing test apps"
adb root
adb install -t -r -g -d $ANDROID_TARGET_OUT_TESTCASES/TranscodingUidPolicy_TestAppA/arm64/TranscodingUidPolicy_TestAppA.apk
adb install -t -r -g -d $ANDROID_TARGET_OUT_TESTCASES/TranscodingUidPolicy_TestAppB/arm64/TranscodingUidPolicy_TestAppB.apk
adb install -t -r -g -d $ANDROID_TARGET_OUT_TESTCASES/TranscodingUidPolicy_TestAppC/arm64/TranscodingUidPolicy_TestAppC.apk

echo "[==========] waiting for device and sync"
adb wait-for-device remount && adb sync
adb shell kill -9 `pid media.transcoding`

#adb shell /data/nativetest64/mediatranscodingservice_tests/mediatranscodingservice_tests
adb shell /data/nativetest/mediatranscodingservice_tests/mediatranscodingservice_tests
