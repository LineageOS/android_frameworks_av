# Fuzzer for libmediaplayerservice
## Table of contents
+ [StagefrightMediaRecorder](#StagefrightMediaRecorder)
+ [StagefrightMetadataRetriever](#StagefrightMetadataRetriever)
+ [MediaPlayer](#MediaPlayer)

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

# <a name="MediaPlayer"></a> Fuzzer for MediaPlayer

MediaPlayerService supports the following data sources:
1. Url (parameter name: `url`)
2. File descriptor (parameter name: `fd`)
3. IStreamSource  (parameter name: `source`)
4. IDataSource (parameter name: `source`)
5. RTP Parameters  (parameter name: `rtpParams`)

MediaPlayerService supports the following parameters:
1. Audio sessions (parameter name: `audioSessionId`)
2. Audio stretch modes (parameter name: `mStretchMode`)
3. Audio fallback modes  (parameter name: `mFallbackMode`)
4. Media parameter keys (parameter name: `key`)
5. Audio Stream Types (parameter name: `streamType`)
6. Media Event Types (parameter name: `msg`)
7. Media Info Types (parameter name: `ext1`)

You can find the possible values in the fuzzer's source code.

#### Steps to run
1. Build the fuzzer
```
  $ mm -j$(nproc) mediaplayer_fuzzer
```
2. To run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/mediaplayer_fuzzer/mediaplayer_fuzzer
```
