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

echo "Copying files to device"

adb shell mkdir -p /data/local/tmp/TranscodingTestAssets

FILES=$ANDROID_BUILD_TOP/frameworks/av/media/libmediatranscoding/tests/assets/TranscodingTestAssets/*
for file in $FILES
do 
adb push --sync $file /data/local/tmp/TranscodingTestAssets
done

echo "Copy done"
