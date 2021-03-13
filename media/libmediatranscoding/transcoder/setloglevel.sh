#!/bin/bash

if [ $# -ne 1 ]
then
    echo "Usage 1: $0 <loglevel>"
    echo "  Set all transcoder log tags to <loglevel>"
    echo "Usage 2: $0 -l"
    echo "  List all transcoder log tags and exit"
    exit 1
fi

# List all log tags
declare -a tags=(
  MediaTranscoder MediaTrackTranscoder VideoTrackTranscoder PassthroughTrackTranscoder
  MediaSampleWriter MediaSampleReader MediaSampleQueue MediaTranscoderTests
  MediaTrackTranscoderTests VideoTrackTranscoderTests PassthroughTrackTranscoderTests
  MediaSampleWriterTests MediaSampleReaderNDKTests MediaSampleQueueTests HdrTranscodeTests)

if [ "$1" == "-l" ]; then
  echo "Transcoder log tags:"
  for tag in "${tags[@]}"; do echo -n "$tag "; done
  echo
  exit 0
fi

level=$1
echo Setting transcoder log level to $level

# Set log level for all tags
for tag in "${tags[@]}"
do
    adb shell setprop log.tag.${tag} $level
done

# Pick up new settings
adb shell stop && adb shell start
