#!/bin/bash

if [ $# -ne 1 ]
then
    echo Usage: $0 loglevel
    exit 1
fi

level=$1
echo Setting transcoder log level to $level

# List all log tags
declare -a tags=(
  MediaTranscoder MediaTrackTranscoder VideoTrackTranscoder PassthroughTrackTranscoder
  MediaSampleWriter MediaSampleReader MediaSampleQueue MediaTranscoderTests
  MediaTrackTranscoderTests VideoTrackTranscoderTests PassthroughTrackTranscoderTests
  MediaSampleWriterTests MediaSampleReaderNDKTests MediaSampleQueueTests)

# Set log level for all tags
for tag in "${tags[@]}"
do
    adb shell setprop log.tag.${tag} $level
done

# Pick up new settings
adb shell stop && adb shell start
