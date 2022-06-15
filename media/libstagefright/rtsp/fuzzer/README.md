# Fuzzers for libstagefright_rtsp

## Table of contents
+ [sdploader_fuzzer](#SDPLoader)
+ [rtp_writer_fuzzer](#ARTPWriter)
+ [packet_source_fuzzer](#packetSource)

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

# <a name="packetSource"></a> Fuzzer for  PacketSource

 PacketSource supports the following parameters:
1. Codec (parameter name: "kCodecs")
2. Format (parameter name: "kFmtp")

| Parameter| Valid Values| Configured Value|
|------------- |-------------| ----- |
|`kCodecs`| 0. `opus`<br/>1. `ISAC`<br/>2. `VP8`<br/>3. `google-data`<br/>4. `G722`<br/>5. `PCMU`<br/>6. `PCMA`<br/>7. `CN`<br/>8. `telephone-event`<br/>9. `VP9`<br/>10. `red`<br/>11. `ulpfec`<br/>12. `rtx`<br/>13. `H264`<br/>14. `iLBC`<br/>15. `H261`<br/>16. `MPV`<br/>17. `H263`<br/>18. `AMR`<br/>19. `AC3`<br/>20. `G723`<br/>21. `G729A`<br/>22. `MP4V-ES`<br/>23. `H265`<br/>24. `H263-2000`<br/>25. `H263-1998`<br/>26. `AMR-WB`<br/>27. `MP4A-LATM`<br/>28. `MP2T`<br/>29. `mpeg4-generic` |Value obtained from FuzzedDataProvider|
|`kFmtp`| <br/>0. `br=`<br/>1. `bw=`<br/>2. `ch-aw-recv=`<br/>3. `mode-change-capability=`<br/>4. `max-red =`<br/>5. `octet-align=`<br/>6. `mode-change-capability=`<br/>7. `profile-level-id=`<br/>8. `packetization-mode=`<br/>9. `profile=`<br/>10. `level=` <br/>11. `apt=`<br/>12. `annexb=`<br/>13. `protocol=`<br/>14. `config=`<br/>15. `streamtype=`<br/>16. `mode=`<br/>17. `sizelength=`<br/>18. `indexlength=`<br/>19. `indexdeltalength=`<br/>20. `minptime=`<br/>21. `useinbandfec=`<br/>22. `maxplaybackrate=`<br/>23. `stereo=`<br/>24. `level-asymmetry-allowed=`<br/>25. `max-fs=`<br/>26. `max-fr=`|Value obtained from FuzzedDataProvider|

#### Steps to run
1. Build the fuzzer
```
  $ mm -j$(nproc) packet_source_fuzzer
```
2. Run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/packet_source_fuzzer/packet_source_fuzzer
```
