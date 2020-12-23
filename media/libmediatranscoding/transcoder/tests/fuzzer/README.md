# Fuzzer for libmediatranscoder

## Plugin Design Considerations
The fuzzer plugin for libmediatranscoder is designed based on the understanding of the
transcoder and tries to achieve the following:

##### Maximize code coverage
The configuration parameters are not hardcoded, but instead selected based on
incoming data. This ensures more code paths are reached by the fuzzer.

Transcoder supports the following parameters:
1. Destination Mime Type (parameter name: `dstMime`)
2. AVC Profile (parameter name: `profile`)
3. HEVC Profile (parameter name: `profile`)
4. AVC Level (parameter name: `level`)
5. HEVC Level (parameter name: `level`)
6. Bitrate (parameter name: `bitrate`)

| Parameter| Valid Values| Configured Value|
|------------- |-------------| ----- |
| `dstMime` | 0. `AMEDIA_MIMETYPE_VIDEO_AVC` 1. `AMEDIA_MIMETYPE_VIDEO_HEVC` | Bit 0 (LSB) of 1st byte of data |
| `profile` for AVC | 0. `PROFILE_AVC_BASELINE` 1. `PROFILE_AVC_CONSTRAINED_BASELINE` 2. `PROFILE_AVC_MAIN`| All bits of 2nd byte of data modulus 3 |
| `profile` for HEVC | 0. `PROFILE_HEVC_MAIN` 1. `PROFILE_HEVC_MAIN_STILL` | All bits of 2nd byte of data modulus 2 |
| `level` for AVC | 0. `LEVEL_AVC_1` 1. `LEVEL_AVC_1B` 2. `LEVEL_AVC_1_1` 3. `LEVEL_AVC_1_2` 4. `LEVEL_AVC_1_3` 5. `LEVEL_AVC_2` 6. `LEVEL_AVC_2_1` 7. `LEVEL_AVC_2_2` 8. `LEVEL_AVC_3` 9. `LEVEL_AVC_3_1` 10. `LEVEL_AVC_3_2` 11. `LEVEL_AVC_4` 12. `LEVEL_AVC_4_1` 13. `LEVEL_AVC_4_2` 14. `LEVEL_AVC_5`| All bits of 3rd byte of data modulus 15 |
| `level` for HEVC | 0. `LEVEL_HEVC_MAIN_1` 1. `LEVEL_HEVC_MAIN_2` 2. `LEVEL_HEVC_MAIN_2_1` 3. `LEVEL_HEVC_MAIN_3` 4. `LEVEL_HEVC_MAIN_3_1` 5. `LEVEL_HEVC_MAIN_4` 6. `LEVEL_HEVC_MAIN_4_1` 7. `LEVEL_HEVC_MAIN_5` 8. `LEVEL_HEVC_MAIN_5_1` 9. `LEVEL_HEVC_MAIN_5_2` | All bits of 3rd byte of data modulus 10 |
| `bitrate` | In the range `0` to `500000000` | All bits of 4th and 5th byte of data |

This also ensures that the plugin is always deterministic for any given input.
##### Maximize utilization of input data
The plugin feeds the entire input data to the transcoder.
This ensures that the plugin tolerates any kind of input (empty, huge,
malformed, etc) and doesnt `exit()` on any input and thereby increasing the
chance of identifying vulnerabilities.

## Build

This describes steps to build media_transcoder_fuzzer binary.

### Android

#### Steps to build
Build the fuzzer
```
  $ mm -j$(nproc) media_transcoder_fuzzer
```
#### Steps to run
Create a directory CORPUS_DIR
```
  $ adb shell mkdir CORPUS_DIR
```
To run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/${TARGET_ARCH}/media_transcoder_fuzzer/media_transcoder_fuzzer CORPUS_DIR
```

## References:
 * http://llvm.org/docs/LibFuzzer.html
 * https://github.com/google/oss-fuzz
