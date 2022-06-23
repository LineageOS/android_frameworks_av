# Fuzzers for libstagefright_rtsp

## Table of contents
+ [sdploader_fuzzer](#SDPLoader)
+ [rtp_writer_fuzzer](#ARTPWriter)

# <a name="SDPLoader"></a> Fuzzer for SDPLoader

SDPLoader supports the following parameters:
1. Flag (parameter name: "flags")
2. URL (parameter name: "url")
3. Header (parameter name: "headers")

| Parameter| Valid Values| Configured Value|
|------------- |-------------| ----- |
|`flags`| `UINT32_MIN`  to  `UINT32_MAX` |Value obtained from FuzzedDataProvider|
|`url`| `String` |Value obtained from FuzzedDataProvider|
|`headers`| `String` |Value obtained from FuzzedDataProvider|

#### Steps to run
1. Build the fuzzer
```
  $ mm -j$(nproc) sdploader_fuzzer
```
2. Run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/sdploader_fuzzer/sdploader_fuzzer
```

# <a name="ARTPWriter"></a> Fuzzer for ARTPWriter

ARTPWriter supports the following parameters:
1. File descriptor (parameter name: "fd")
2. Local Ip (parameter name: "localIp")
3. Local Port (parameter name: "localPort")
4. Remote Ip (parameter name: "remoteIp")
5. Remote Port (parameter name: "remotePort")
6. Sequence No (parameter name: "seqNo")
7. OpponentID (parameter name: "opponentID")
8. Bit Rate (parameter name: "bitrate")
9. kKeyMIMETypeArray (parameter name: "mimeType")

| Parameter| Valid Values| Configured Value|
|------------- |-------------| ----- |
|`localIp`| `String` |Value obtained from FuzzedDataProvider|
|`localPort`| `UINT32_MIN`  to  `UINT32_MAX` |Value obtained from FuzzedDataProvider|
|`remoteIp`| `String` |Value obtained from FuzzedDataProvider|
|`remotePort`| `UINT32_MIN`  to  `UINT32_MAX` |Value obtained from FuzzedDataProvider|
|`seqNo`| `0`  to  `10000000` |Value obtained from FuzzedDataProvider|
|`opponentID`| `UINT32_MIN`  to  `UINT32_MAX` |Value obtained from FuzzedDataProvider|
|`bitrate`| `UINT32_MIN`  to  `UINT32_MAX` |Value obtained from FuzzedDataProvider|
|`mimeType`| 0. `MEDIA_MIMETYPE_VIDEO_AVC`<br> 1. `MEDIA_MIMETYPE_VIDEO_HEVC`<br> 2. `MEDIA_MIMETYPE_VIDEO_H263`<br> 3. `MEDIA_MIMETYPE_AUDIO_AMR_NB`<br> 4. `MEDIA_MIMETYPE_AUDIO_AMR_WB`|Value obtained from FuzzedDataProvider|

#### Steps to run
1. Build the fuzzer
```
  $ mm -j$(nproc) rtp_writer_fuzzer
```
2. Run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/rtp_writer_fuzzer/rtp_writer_fuzzer
```
