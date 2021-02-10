#!/bin/bash

# Exit on compilation error.
set -e

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

# Push the files onto the device.
. $ANDROID_BUILD_TOP/frameworks/av/media/libmediatranscoding/tests/push_assets.sh

echo "========================================"

# Don't exit if a test fails.
set +e

echo "testing MediaSampleReaderNDK"
adb shell ASAN_OPTIONS=detect_container_overflow=0 /data/nativetest64/MediaSampleReaderNDKTests/MediaSampleReaderNDKTests

echo "testing MediaSampleQueue"
adb shell ASAN_OPTIONS=detect_container_overflow=0 /data/nativetest64/MediaSampleQueueTests/MediaSampleQueueTests

echo "testing MediaTrackTranscoder"
adb shell ASAN_OPTIONS=detect_container_overflow=0 /data/nativetest64/MediaTrackTranscoderTests/MediaTrackTranscoderTests

echo "testing VideoTrackTranscoder"
adb shell ASAN_OPTIONS=detect_container_overflow=0 /data/nativetest64/VideoTrackTranscoderTests/VideoTrackTranscoderTests

echo "testing PassthroughTrackTranscoder"
adb shell ASAN_OPTIONS=detect_container_overflow=0 /data/nativetest64/PassthroughTrackTranscoderTests/PassthroughTrackTranscoderTests

echo "testing MediaSampleWriter"
adb shell ASAN_OPTIONS=detect_container_overflow=0 /data/nativetest64/MediaSampleWriterTests/MediaSampleWriterTests

echo "testing MediaTranscoder"
adb shell ASAN_OPTIONS=detect_container_overflow=0 /data/nativetest64/MediaTranscoderTests/MediaTranscoderTests
