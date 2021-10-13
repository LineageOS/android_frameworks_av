# Fuzzer for libmediaplayerservice
## Table of contents
+ [StagefrightMediaRecorder](#StagefrightMediaRecorder)

# <a name="StagefrightMediaRecorder"></a> Fuzzer for StagefrightMediaRecorder

StagefrightMediaRecorder supports the following parameters:
1. Output Formats (parameter name: `setOutputFormat`)
2. Audio Encoders (parameter name: `setAudioEncoder`)
3. Video Encoders (parameter name: `setVideoEncoder`)
4. Audio Sources (parameter name: `setAudioSource`)
5. Video Sources (parameter name: `setVideoSource`)
6. Microphone Direction (parameter name: `setMicrophoneDirection`)

You can find the possible values in the fuzzer's source code.

#### Steps to run
1. Build the fuzzer
```
  $ mm -j$(nproc) mediarecorder_fuzzer
```
2. Run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/mediarecorder_fuzzer/mediarecorder_fuzzer
```
