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

# Push the files onto the device.
. $ANDROID_BUILD_TOP/frameworks/av/media/libmediatranscoding/tests/push_assets.sh

echo "[==========] installing test apps"
adb root
adb install -t -r -g -d $ANDROID_TARGET_OUT_TESTCASES/TranscodingUidPolicy_TestAppA/arm64/TranscodingUidPolicy_TestAppA.apk
adb install -t -r -g -d $ANDROID_TARGET_OUT_TESTCASES/TranscodingUidPolicy_TestAppB/arm64/TranscodingUidPolicy_TestAppB.apk
adb install -t -r -g -d $ANDROID_TARGET_OUT_TESTCASES/TranscodingUidPolicy_TestAppC/arm64/TranscodingUidPolicy_TestAppC.apk

echo "[==========] waiting for device and sync"
adb wait-for-device remount && adb sync

echo "[==========] running simulated tests"
adb shell setprop debug.transcoding.simulated_transcoder true
adb shell kill -9 `pid media.transcoding`
#adb shell /data/nativetest64/mediatranscodingservice_simulated_tests/mediatranscodingservice_simulated_tests
adb shell /data/nativetest/mediatranscodingservice_simulated_tests/mediatranscodingservice_simulated_tests

echo "[==========] running real tests"
adb shell setprop debug.transcoding.simulated_transcoder false
adb shell kill -9 `pid media.transcoding`
#adb shell /data/nativetest64/mediatranscodingservice_real_tests/mediatranscodingservice_real_tests
adb shell /data/nativetest/mediatranscodingservice_real_tests/mediatranscodingservice_real_tests

echo "[==========] running resource tests"
adb shell kill -9 `pid media.transcoding`
#adb shell /data/nativetest64/mediatranscodingservice_resource_tests/mediatranscodingservice_resource_tests
adb shell /data/nativetest/mediatranscodingservice_resource_tests/mediatranscodingservice_resource_tests

echo "[==========] removing debug properties"
adb shell setprop debug.transcoding.simulated_transcoder \"\"
adb shell kill -9 `pid media.transcoding`
