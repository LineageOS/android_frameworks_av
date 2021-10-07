# Fuzzer for libaudioflinger

## Plugin Design Considerations
The fuzzer plugin for libaudioflinger is designed based on the understanding of the
library and tries to achieve the following:

##### Maximize code coverage
The configuration parameters are not hardcoded, but instead selected based on
incoming data. This ensures more code paths are reached by the fuzzer. The fuzzer
covers libaudioflinger APIs as called from libaudioclient through IPC.

libaudioflinger supports the following parameters:
1. Unique IDs (parameter name: `uniqueId`)
2. Audio Mode (parameter name: `mode`)
3. Session ID (parameter name: `sessionId`)
4. Encapsulation Mode (parameter name: `encapsulationMode`)
5. Audio Port Role (parameter name: `portRole`)
6. Audio Port Type (parameter name: `portType`)
7. Audio Stream Type (parameter name: `streamType`)
8. Audio Format (parameter name: `format`)
9. Audio Channel Mask (parameter name: `channelMask`)
10. Usage (parameter name: `usage`)
11. Audio Content Type (parameter name: `contentType`)
12. Input Source (parameter name: `inputSource`)
13. Input Flags (parameter name: `inputFlags`)
14. Output Flags (parameter name: `outputFlags`)
15. Audio Gain Mode (parameter name: `gainMode`)
16. Audio Device (parameter name: `device`)

| Parameter| Valid Values| Configured Value|
|------------- |-------------| ----- |
| `uniqueId`   | 0. `AUDIO_UNIQUE_ID_USE_UNSPECIFIED` 1. `AUDIO_UNIQUE_ID_USE_SESSION` 2. `AUDIO_UNIQUE_ID_USE_MODULE` 3. `AUDIO_UNIQUE_ID_USE_EFFECT` 4. `AUDIO_UNIQUE_ID_USE_PATCH` 5. `AUDIO_UNIQUE_ID_USE_OUTPUT` 6. `AUDIO_UNIQUE_ID_USE_INPUT` 7. `AUDIO_UNIQUE_ID_USE_CLIENT` 8. `AUDIO_UNIQUE_ID_USE_MAX` | Value obtained from FuzzedDataProvider
| `mode`   | 0.`AUDIO_MODE_INVALID` 1. `AUDIO_MODE_CURRENT` 2. ` AUDIO_MODE_NORMAL` 3. `AUDIO_MODE_RINGTONE` 4. `AUDIO_MODE_IN_CALL` 5. `AUDIO_MODE_IN_COMMUNICATION` 6. `AUDIO_MODE_CALL_SCREEN` | Value obtained from FuzzedDataProvider|
| `sessionId`   | 0. `AUDIO_SESSION_NONE` 1. `AUDIO_SESSION_OUTPUT_STAGE` 2. `AUDIO_SESSION_DEVICE` | Value obtained from FuzzedDataProvider|
| `encapsulationMode`   | 0. `AUDIO_ENCAPSULATION_MODE_NONE` 1. `AUDIO_ENCAPSULATION_MODE_ELEMENTARY_STREAM` 2. `AUDIO_ENCAPSULATION_MODE_HANDLE` | Value obtained from FuzzedDataProvider|
| `portRole`   | 0. `AUDIO_PORT_ROLE_NONE` 1. `AUDIO_PORT_ROLE_SOURCE` 2. `AUDIO_PORT_ROLE_SINK` | Value obtained from FuzzedDataProvider|
| `portType`   | 0. `AUDIO_PORT_TYPE_NONE` 1. `AUDIO_PORT_TYPE_DEVICE` 2. `AUDIO_PORT_TYPE_MIX` 3. `AUDIO_PORT_TYPE_SESSION`| Value obtained from FuzzedDataProvider|
| `streamType` | 15 values of type `audio_stream_type_t` | Value chosen from valid values by obtaining index from FuzzedDataProvider |
| `format` | 77 values of type `audio_format_t` | Value chosen from valid values by obtaining index from FuzzedDataProvider |
| `channelMask` | 83 values of type `audio_channel_mask_t` | Value chosen from valid values by obtaining index from FuzzedDataProvider |
| `usage` | 22 values of type `audio_usage_t` | Value chosen from valid values by obtaining index from FuzzedDataProvider |
| `contentType` | 5 values of type `audio_content_type_t` | Value chosen from valid values by obtaining index from FuzzedDataProvider |
| `inputSource` | 14 values of type `audio_source_t` | Value chosen from valid values by obtaining index from FuzzedDataProvider |
| `inputFlags` | 9 values of type `audio_input_flags_t` | Value chosen from valid values by obtaining index from FuzzedDataProvider |
| `outputFlags` | 16 values of type `audio_output_flags_t` | Value chosen from valid values by obtaining index from FuzzedDataProvider |
| `gainMode` | 3 values of type `audio_gain_mode_t` | Value chosen from valid values by obtaining index from FuzzedDataProvider |
| `device` | 66 values of type `audio_devices_t` | Value chosen from valid values by obtaining index from FuzzedDataProvider |

This also ensures that the plugin is always deterministic for any given input.

##### Maximize utilization of input data
The plugin tolerates any kind of input (empty, huge,
malformed, etc) and doesn't `exit()` on any input and thereby increasing the
chance of identifying vulnerabilities.

## Build

This describes steps to build audioflinger_fuzzer binary.

### Android

#### Steps to build
Build the fuzzer
```
  $ mm -j$(nproc) audioflinger_fuzzer
```

#### Steps to run
Create a directory CORPUS_DIR and copy some files to that folder
Push this directory to device.

To run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/audioflinger_fuzzer/audioflinger_fuzzer CORPUS_DIR
```

## References:
 * http://llvm.org/docs/LibFuzzer.html
 * https://github.co
