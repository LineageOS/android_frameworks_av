#!/bin/bash
#
# Pushes the assets to the /data/local/tmp.
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

  adb root && adb wait-for-device remount
fi

#TODO(hkuang): Check if the destination folder already exists. If so, skip the copying.
echo "Copying files to device"
adb push $ANDROID_BUILD_TOP/frameworks/av/media/libmediatranscoding/tests/assets /data/local/tmp/TranscodingTestAssets
echo "Copy done"
