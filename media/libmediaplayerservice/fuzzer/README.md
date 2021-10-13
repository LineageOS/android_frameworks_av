# Fuzzer for libmediaplayerservice
## Table of contents
+ [StagefrightMediaRecorder](#StagefrightMediaRecorder)
+ [StagefrightMetadataRetriever](#StagefrightMetadataRetriever)

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

# <a name="StagefrightMetadataRetriever"></a> Fuzzer for StagefrightMetadataRetriever

StagefrightMetadataRetriever supports the following data sources:
1. Url (parameter name: `url`)
2. File descriptor (parameter name: `fd`)
3. DataSource (parameter name: `source`)

| Parameter| Valid Values| Configured Value|
|------------- |-------------| ----- |
| `url` | Url of data source | Value obtained from FuzzedDataProvider |
| `fd` | File descriptor value of input file | Value obtained from FuzzedDataProvider |
| `source` | DataSource object | Data obtained from FuzzedDataProvider |

#### Steps to run
1. Build the fuzzer
```
  $ mm -j$(nproc) metadataretriever_fuzzer
```
2. To run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/metadataretriever_fuzzer/metadataretriever_fuzzer
```
