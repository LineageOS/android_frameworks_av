#!/bin/bash
#
# Run tests in this directory.
#

if [ "$SYNC_FINISHED" != true ]; then
  if [ -z "$ANDROID_BUILD_TOP" ]; then
      echo "Android build environment not set"
      exit -1
  fi

  # ensure we have mm
  . $ANDROID_BUILD_TOP/build/envsetup.sh

  mm

  echo "waiting for device"

  adb root && adb wait-for-device remount && adb sync
fi

echo "========================================"

echo "testing ResourceManagerService"
#adb shell /data/nativetest64/ResourceManagerService_test/ResourceManagerService_test
adb shell /data/nativetest/ResourceManagerService_test/ResourceManagerService_test

echo "testing ServiceLog"
#adb shell /data/nativetest64/ServiceLog_test/ServiceLog_test
adb shell /data/nativetest/ServiceLog_test/ServiceLog_test

echo "testing ResourceObserverService"
#adb shell /data/nativetest64/ResourceObserverService_test/ResourceObserverService_test
adb shell /data/nativetest/ResourceObserverService_test/ResourceObserverService_test
