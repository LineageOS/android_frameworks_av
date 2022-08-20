# Fuzzers for libmediandk

## Table of contents
+ [ndk_crypto_fuzzer](#NdkCrypto)
+ [ndk_image_reader_fuzzer](#NdkImageReader)
+ [ndk_extractor_fuzzer](#NdkExtractor)
+ [ndk_mediaformat_fuzzer](#NdkMediaFormat)
+ [ndk_drm_fuzzer](#NdkDrm)
+ [ndk_mediamuxer_fuzzer](#NdkMediaMuxer)
+ [ndk_sync_codec_fuzzer](#NdkSyncCodec)

# <a name="NdkCrypto"></a> Fuzzer for NdkCrypto

NdkCrypto supports the following parameters:
    UniversalIdentifier (parameter name: "uuid")

| Parameter| Valid Values |Configured Value|
|-------------|----------|----- |
| `uuid`| `Array`| Value obtained from FuzzedDataProvider|

#### Steps to run
1. Build the fuzzer
```
  $ mm -j$(nproc) ndk_crypto_fuzzer
```
2. Run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/ndk_crypto_fuzzer/ndk_crypto_fuzzer
```

# <a name="NdkImageReader"></a> Fuzzer for NdkImageReader

NdkImageReader supports the following parameters:
1. Width (parameter name: "imageWidth")
2. Height (parameter name: "imageHeight")
3. Format (parameter name: "imageFormat")
4. Usage (parameter name: "imageUsage")
5. Max images (parameter name: "imageMaxCount")

| Parameter| Valid Values |Configured Value|
|-------------|----------|----- |
| `width`| `1 to INT_MAX`| Value obtained from FuzzedDataProvider|
| `height`| `1 to INT_MAX`| Value obtained from FuzzedDataProvider|
| `format`| `1 to INT_MAX`| Value obtained from FuzzedDataProvider|
| `usage`| `1 to INT_MAX`| Value obtained from FuzzedDataProvider|
| `maxImages`| `1 to android::BufferQueue::MAX_MAX_ACQUIRED_BUFFERS`| Value obtained from FuzzedDataProvider|

#### Steps to run
1. Build the fuzzer
```
  $ mm -j$(nproc) ndk_image_reader_fuzzer
```
2. Run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/ndk_image_reader_fuzzer/ndk_image_reader_fuzzer
```

# <a name="NdkExtractor"></a>Fuzzer for NdkExtractor

NdkExtractor supports the following parameters:
1. SeekMode (parameter name: "mode")

| Parameter| Valid Values |Configured Value|
|-------------|----------|----- |
|`mode`|0.`AMEDIAEXTRACTOR_SEEK_PREVIOUS_SYNC`,<br/>1.`AMEDIAEXTRACTOR_SEEK_NEXT_SYNC`,<br/>2.`AMEDIAEXTRACTOR_SEEK_CLOSEST_SYNC`| Value obtained from FuzzedDataProvider|

#### Steps to run
1. Build the fuzzer
```
  $ mm -j$(nproc) ndk_extractor_fuzzer
```
2. Run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/ndk_extractor_fuzzer/ndk_extractor_fuzzer /data/fuzz/${TARGET_ARCH}/ndk_extractor_fuzzer/corpus
```


# <a name="NdkMediaFormat"></a>Fuzzer for NdkMediaFormat

NdkMediaFormat supports the following parameters:
1. Name (parameter name: "name")

| Parameter| Valid Values |Configured Value|
|-------------|----------|----- |
|`name`|1.`AMEDIAFORMAT_KEY_AAC_DRC_ATTENUATION_FACTOR`, 2.`AMEDIAFORMAT_KEY_AAC_DRC_BOOST_FACTOR`, 3.`AMEDIAFORMAT_KEY_AAC_DRC_HEAVY_COMPRESSION`, 4.`AMEDIAFORMAT_KEY_AAC_DRC_TARGET_REFERENCE_LEVEL`, 5.`AMEDIAFORMAT_KEY_AAC_ENCODED_TARGET_LEVEL`, 6.`AMEDIAFORMAT_KEY_AAC_MAX_OUTPUT_CHANNEL_COUNT`, 7.`AMEDIAFORMAT_KEY_AAC_PROFILE`, 8.`AMEDIAFORMAT_KEY_AAC_SBR_MODE`, 9.`AMEDIAFORMAT_KEY_ALBUM`, 10.`AMEDIAFORMAT_KEY_ALBUMART`, 11.`AMEDIAFORMAT_KEY_ALBUMARTIST`, 12.`AMEDIAFORMAT_KEY_ARTIST`, 13.`AMEDIAFORMAT_KEY_AUDIO_PRESENTATION_INFO`, 14.`AMEDIAFORMAT_KEY_AUDIO_PRESENTATION_PRESENTATION_ID`, 15.`AMEDIAFORMAT_KEY_AUDIO_PRESENTATION_PROGRAM_ID`, 16.`AMEDIAFORMAT_KEY_AUDIO_SESSION_ID`, 17.`AMEDIAFORMAT_KEY_AUTHOR`, 18.`AMEDIAFORMAT_KEY_BITRATE_MODE`, 19.`AMEDIAFORMAT_KEY_BIT_RATE`, 20.`AMEDIAFORMAT_KEY_BITS_PER_SAMPLE`, 21.`AMEDIAFORMAT_KEY_CAPTURE_RATE`, 22.`AMEDIAFORMAT_KEY_CDTRACKNUMBER`, 23.`AMEDIAFORMAT_KEY_CHANNEL_COUNT`, 24.`AMEDIAFORMAT_KEY_CHANNEL_MASK`, 25.`AMEDIAFORMAT_KEY_COLOR_FORMAT`, 26.`AMEDIAFORMAT_KEY_COLOR_RANGE`, 27.`AMEDIAFORMAT_KEY_COLOR_STANDARD`, 28.`AMEDIAFORMAT_KEY_COLOR_TRANSFER`, 29.`AMEDIAFORMAT_KEY_COMPILATION`, 30.`AMEDIAFORMAT_KEY_COMPLEXITY`, 31.`AMEDIAFORMAT_KEY_COMPOSER`, 32.`AMEDIAFORMAT_KEY_CREATE_INPUT_SURFACE_SUSPENDED`, 33.`AMEDIAFORMAT_KEY_CRYPTO_DEFAULT_IV_SIZE`, 34.`AMEDIAFORMAT_KEY_CRYPTO_ENCRYPTED_BYTE_BLOCK`, 35.`AMEDIAFORMAT_KEY_CRYPTO_ENCRYPTED_SIZES`, 36.`AMEDIAFORMAT_KEY_CRYPTO_IV`, 37.`AMEDIAFORMAT_KEY_CRYPTO_KEY`, 38.`AMEDIAFORMAT_KEY_CRYPTO_MODE`, 39.`AMEDIAFORMAT_KEY_CRYPTO_PLAIN_SIZES`, 40.`AMEDIAFORMAT_KEY_CRYPTO_SKIP_BYTE_BLOCK`, 41.`AMEDIAFORMAT_KEY_CSD`, 42.`AMEDIAFORMAT_KEY_CSD_0`, 43.`AMEDIAFORMAT_KEY_CSD_1`, 44.`AMEDIAFORMAT_KEY_CSD_2`, 45.`AMEDIAFORMAT_KEY_CSD_AVC`, 46.`AMEDIAFORMAT_KEY_CSD_HEVC`, 47.`AMEDIAFORMAT_KEY_D263`, 48.`AMEDIAFORMAT_KEY_DATE`, 49.`AMEDIAFORMAT_KEY_DISCNUMBER`, 50.`AMEDIAFORMAT_KEY_DISPLAY_CROP`, 51.`AMEDIAFORMAT_KEY_DISPLAY_HEIGHT`, 52.`AMEDIAFORMAT_KEY_DISPLAY_WIDTH`, 53.`AMEDIAFORMAT_KEY_DURATION`, 54.`AMEDIAFORMAT_KEY_ENCODER_DELAY`, 55.`AMEDIAFORMAT_KEY_ENCODER_PADDING`, 56.`AMEDIAFORMAT_KEY_ESDS`, 57.`AMEDIAFORMAT_KEY_EXIF_OFFSET`, 58.`AMEDIAFORMAT_KEY_EXIF_SIZE`, 59.`AMEDIAFORMAT_KEY_FLAC_COMPRESSION_LEVEL`, 60.`AMEDIAFORMAT_KEY_FRAME_COUNT`, 61.`AMEDIAFORMAT_KEY_FRAME_RATE`, 62.`AMEDIAFORMAT_KEY_GENRE`, 63.`AMEDIAFORMAT_KEY_GRID_COLUMNS`, 64.`AMEDIAFORMAT_KEY_GRID_ROWS`, 65.`AMEDIAFORMAT_KEY_HAPTIC_CHANNEL_COUNT`, 66.`AMEDIAFORMAT_KEY_HDR_STATIC_INFO`, 67.`AMEDIAFORMAT_KEY_HDR10_PLUS_INFO`, 68.`AMEDIAFORMAT_KEY_HEIGHT`, 69.`AMEDIAFORMAT_KEY_ICC_PROFILE`, 70.`AMEDIAFORMAT_KEY_INTRA_REFRESH_PERIOD`, 71.`AMEDIAFORMAT_KEY_IS_ADTS`, 72.`AMEDIAFORMAT_KEY_IS_AUTOSELECT`, 73.`AMEDIAFORMAT_KEY_IS_DEFAULT`, 74.`AMEDIAFORMAT_KEY_IS_FORCED_SUBTITLE`, 75.`AMEDIAFORMAT_KEY_IS_SYNC_FRAME`, 76.`AMEDIAFORMAT_KEY_I_FRAME_INTERVAL`, 77.`AMEDIAFORMAT_KEY_LANGUAGE`, 78.`AMEDIAFORMAT_KEY_LAST_SAMPLE_INDEX_IN_CHUNK`, 79.`AMEDIAFORMAT_KEY_LATENCY`, 80.`AMEDIAFORMAT_KEY_LEVEL`, 81.`AMEDIAFORMAT_KEY_LOCATION`, 82.`AMEDIAFORMAT_KEY_LOOP`, 83.`AMEDIAFORMAT_KEY_LOW_LATENCY`, 84.`AMEDIAFORMAT_KEY_LYRICIST`, 85.`AMEDIAFORMAT_KEY_MANUFACTURER`, 86.`AMEDIAFORMAT_KEY_MAX_BIT_RATE`, 87.`AMEDIAFORMAT_KEY_MAX_FPS_TO_ENCODER`, 88.`AMEDIAFORMAT_KEY_MAX_HEIGHT`, 89.`AMEDIAFORMAT_KEY_MAX_INPUT_SIZE`, 90.`AMEDIAFORMAT_KEY_MAX_PTS_GAP_TO_ENCODER`, 91.`AMEDIAFORMAT_KEY_MAX_WIDTH`, 92.`AMEDIAFORMAT_KEY_MIME`, 93.`AMEDIAFORMAT_KEY_MPEG_USER_DATA`, 94.`AMEDIAFORMAT_KEY_MPEG2_STREAM_HEADER`, 95.`AMEDIAFORMAT_KEY_MPEGH_COMPATIBLE_SETS`, 96.`AMEDIAFORMAT_KEY_MPEGH_PROFILE_LEVEL_INDICATION`, 97.`AMEDIAFORMAT_KEY_MPEGH_REFERENCE_CHANNEL_LAYOUT`, 98.`AMEDIAFORMAT_KEY_OPERATING_RATE`, 99.`AMEDIAFORMAT_KEY_PCM_ENCODING`, 100.`AMEDIAFORMAT_KEY_PICTURE_TYPE`, 101.`AMEDIAFORMAT_KEY_PRIORITY`, 102.`AMEDIAFORMAT_KEY_PROFILE`, 103.`AMEDIAFORMAT_KEY_PCM_BIG_ENDIAN`, 104.`AMEDIAFORMAT_KEY_PSSH`, 105.`AMEDIAFORMAT_KEY_PUSH_BLANK_BUFFERS_ON_STOP`, 106.`AMEDIAFORMAT_KEY_REPEAT_PREVIOUS_FRAME_AFTER`, 107.`AMEDIAFORMAT_KEY_ROTATION`, 108.`AMEDIAFORMAT_KEY_SAMPLE_FILE_OFFSET`, 109.`AMEDIAFORMAT_KEY_SAMPLE_RATE`, 110.`AMEDIAFORMAT_KEY_SAMPLE_TIME_BEFORE_APPEND`, 111.`AMEDIAFORMAT_KEY_SAR_HEIGHT`, 112.`AMEDIAFORMAT_KEY_SAR_WIDTH`, 113.`AMEDIAFORMAT_KEY_SEI`, 114.`AMEDIAFORMAT_KEY_SLICE_HEIGHT`, 115.`AMEDIAFORMAT_KEY_SLOW_MOTION_MARKERS`, 116.`AMEDIAFORMAT_KEY_STRIDE`, 117.`AMEDIAFORMAT_KEY_TARGET_TIME`, 118.`AMEDIAFORMAT_KEY_TEMPORAL_LAYER_COUNT`, 119.`AMEDIAFORMAT_KEY_TEMPORAL_LAYER_ID`, 120.`AMEDIAFORMAT_KEY_TEMPORAL_LAYERING`, 121.`AMEDIAFORMAT_KEY_TEXT_FORMAT_DATA`, 122.`AMEDIAFORMAT_KEY_THUMBNAIL_CSD_AV1C`, 123.`AMEDIAFORMAT_KEY_THUMBNAIL_CSD_HEVC`, 124.`AMEDIAFORMAT_KEY_THUMBNAIL_HEIGHT`, 125.`AMEDIAFORMAT_KEY_THUMBNAIL_TIME`, 126.`AMEDIAFORMAT_KEY_THUMBNAIL_WIDTH`, 127.`AMEDIAFORMAT_KEY_TILE_HEIGHT`, 128.`AMEDIAFORMAT_KEY_TILE_WIDTH`, 129.`AMEDIAFORMAT_KEY_TIME_US`, 130.`AMEDIAFORMAT_KEY_TITLE`, 131.`AMEDIAFORMAT_KEY_TRACK_ID`, 132.`AMEDIAFORMAT_KEY_TRACK_INDEX`, 133.`AMEDIAFORMAT_KEY_VALID_SAMPLES`, 134.`AMEDIAFORMAT_KEY_VIDEO_ENCODING_STATISTICS_LEVEL`, 135.`AMEDIAFORMAT_KEY_VIDEO_QP_AVERAGE`, 136.`AMEDIAFORMAT_VIDEO_QP_B_MAX`, 137.`AMEDIAFORMAT_VIDEO_QP_B_MIN`, 138.`AMEDIAFORMAT_VIDEO_QP_I_MAX`, 139.`AMEDIAFORMAT_VIDEO_QP_I_MIN`, 140.`AMEDIAFORMAT_VIDEO_QP_MAX`, 141.`AMEDIAFORMAT_VIDEO_QP_MIN`, 142.`AMEDIAFORMAT_VIDEO_QP_P_MAX`, 143.`AMEDIAFORMAT_VIDEO_QP_P_MIN`, 144.`AMEDIAFORMAT_KEY_WIDTH`, 145.`AMEDIAFORMAT_KEY_XMP_OFFSET`, 146.`AMEDIAFORMAT_KEY_XMP_SIZE`, 147.`AMEDIAFORMAT_KEY_YEAR`| Value obtained from FuzzedDataProvider|

#### Steps to run
1. Build the fuzzer
```
  $ mm -j$(nproc) ndk_mediaformat_fuzzer
```
2. Run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/${TARGET_ARCH}/ndk_mediaformat_fuzzer/ndk_mediaformat_fuzzer /data/fuzz/${TARGET_ARCH}/ndk_mediaformat_fuzzer/corpus
```

# <a name="NdkDrm"></a> Fuzzer for NdkDrm

NdkDrm supports the following parameters:
1. ValidUUID(parameter name: "kCommonPsshBoxUUID" and "kClearKeyUUID")
2. MimeType(parameter name: "kMimeType")
3. MediaUUID(parameter name: "MediaUUID")

| Parameter| Valid Values| Configured Value|
|------------- |-------------| ----- |
|`ValidUUID`| 0.`kCommonPsshBoxUUID`,<br/> 1.`kClearKeyUUID`,<br/> 2.`kInvalidUUID`|Value obtained from FuzzedDataProvider|
|`kMimeType`| 0.`video/mp4`,<br/> 1.`audio/mp4`|Value obtained from FuzzedDataProvider|
|`MediaUUID`| 0.`INVALID_UUID`,<br/> 1.`PSSH_BOX_UUID`,<br/> 2.`CLEARKEY_UUID`|Value obtained from FuzzedDataProvider|

#### Steps to run
1. Build the fuzzer
```
  $ mm -j$(nproc) ndk_drm_fuzzer
```
2. Run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/ndk_drm_fuzzer/ndk_drm_fuzzer
```

# <a name="NdkMediaMuxer"></a>Fuzzer for NdkMediaMuxer

NdkMediaMuxer supports the following parameters:
1. OutputFormat (parameter name: "outputFormat")
2. AppendMode (parameter name: "appendMode")

| Parameter| Valid Values |Configured Value|
|-------------|----------|----- |
|`outputFormat`|0.`AMEDIAMUXER_OUTPUT_FORMAT_MPEG_4`,<br/>1.`AMEDIAMUXER_OUTPUT_FORMAT_WEBM`,<br/>2.`AMEDIAMUXER_OUTPUT_FORMAT_THREE_GPP`| Value obtained from FuzzedDataProvider|
|`appendMode`|0.`AMEDIAMUXER_APPEND_IGNORE_LAST_VIDEO_GOP`,<br/>1.`AMEDIAMUXER_APPEND_TO_EXISTING_DATA`| Value obtained from FuzzedDataProvider|

#### Steps to run
1. Build the fuzzer
```
  $ mm -j$(nproc) ndk_mediamuxer_fuzzer
```
2. Run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/ndk_mediamuxer_fuzzer/ndk_mediamuxer_fuzzer
```

# <a name="NdkSyncCodec"></a>Fuzzer for NdkSyncCodec

#### Steps to run
1. Build the fuzzer
```
  $ mm -j$(nproc) ndk_sync_codec_fuzzer
```
2. Run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/ndk_sync_codec_fuzzer/ndk_sync_codec_fuzzer
```
