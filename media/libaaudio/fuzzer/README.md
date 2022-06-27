# Fuzzer for libaaudio

## Plugin Design Considerations
The fuzzer plugin for `libaaudio` are designed based on the understanding of the
source code and tries to achieve the following:

##### Maximize code coverage
The configuration parameters are not hardcoded, but instead selected based on
incoming data. This ensures more code paths are reached by the fuzzer.

Fuzzers assigns values to the following parameters to pass on to libaaudio:
1. Device Id (parameter name: `deviceId`)
2. Sampling Rate (parameter name: `sampleRate`)
3. Number of channels (parameter name: `channelCount`)
4. Audio Travel Direction (parameter name: `direction`)
5. Audio Format (parameter name: `format`)
6. Audio Sharing Mode (parameter name: `sharingMode`)
7. Audio Usage (parameter name: `usage`)
8. Audio Content type (parameter name: `contentType`)
9. Audio Input Preset (parameter name: `inputPreset`)
10. Audio Privacy Sensitivity (parameter name: `privacySensitive`)
11. Buffer Capacity In Frames (parameter name: `frames`)
12. Performance Mode (parameter name: `mode`)
13. Allowed Capture Policy (parameter name: `allowedCapturePolicy`)
14. Session Id (parameter name: `sessionId`)
15. Frames per Data Callback (parameter name: `framesPerDataCallback`)
16. MMap Policy (parameter name: `policy`)

| Parameter| Valid Values| Configured Value|
|------------- |-------------| ----- |
| `deviceId` | Any value of type `int32_t`  | Value obtained from FuzzedDataProvider |
| `sampleRate` | Any value of type `int32_t`  | Value obtained from FuzzedDataProvider |
| `channelCount` |  Any value of type `int32_t` | Value obtained from FuzzedDataProvider |
| `direction` | 0. `AAUDIO_DIRECTION_OUTPUT` 1. `AAUDIO_DIRECTION_INPUT` | Value obtained from FuzzedDataProvider |
| `format` | 0. `AAUDIO_FORMAT_INVALID` 1. `AAUDIO_FORMAT_UNSPECIFIED` 2. `AAUDIO_FORMAT_PCM_I16` 3. `AAUDIO_FORMAT_PCM_FLOAT` | Value obtained from FuzzedDataProvider |
| `sharingMode` | 0. `AAUDIO_SHARING_MODE_EXCLUSIVE` 1. `AAUDIO_SHARING_MODE_SHARED` | Value obtained from FuzzedDataProvider |
| `usage` | 0. `AAUDIO_USAGE_MEDIA` 1. `AAUDIO_USAGE_VOICE_COMMUNICATION` 2. `AAUDIO_USAGE_VOICE_COMMUNICATION_SIGNALLING` 3. `AAUDIO_USAGE_ALARM` 4. `AAUDIO_USAGE_NOTIFICATION` 5. `AAUDIO_USAGE_NOTIFICATION_RINGTONE` 6. `AAUDIO_USAGE_NOTIFICATION_EVENT` 7. `AAUDIO_USAGE_ASSISTANCE_ACCESSIBILITY` 8. `AAUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE` 9. `AAUDIO_USAGE_ASSISTANCE_SONIFICATION` 10. `AAUDIO_USAGE_GAME` 11. `AAUDIO_USAGE_ASSISTANT` 12. `AAUDIO_SYSTEM_USAGE_EMERGENCY` 13. `AAUDIO_SYSTEM_USAGE_SAFETY` 14. `AAUDIO_SYSTEM_USAGE_VEHICLE_STATUS` 15. `AAUDIO_SYSTEM_USAGE_ANNOUNCEMENT` | Value obtained from FuzzedDataProvider |
| `contentType` | 0. `AAUDIO_CONTENT_TYPE_SPEECH` 1. `AAUDIO_CONTENT_TYPE_MUSIC` 2. `AAUDIO_CONTENT_TYPE_MOVIE` 3. `AAUDIO_CONTENT_TYPE_SONIFICATION` | Value obtained from FuzzedDataProvider |
| `inputPreset` | 0. `AAUDIO_INPUT_PRESET_GENERIC` 1. `AAUDIO_INPUT_PRESET_CAMCORDER` 2. `AAUDIO_INPUT_PRESET_VOICE_RECOGNITION` 3. `AAUDIO_INPUT_PRESET_VOICE_COMMUNICATION` 4. `AAUDIO_INPUT_PRESET_UNPROCESSED` 5. `AAUDIO_INPUT_PRESET_VOICE_PERFORMANCE` | Value obtained from FuzzedDataProvider |
| `privacySensitive` | 0. `true` 1. `false` | Value obtained from FuzzedDataProvider |
| `frames` | Any value of type `int32_t`  | Value obtained from FuzzedDataProvider |
| `mode` | 0. `AAUDIO_PERFORMANCE_MODE_NONE` 1. `AAUDIO_PERFORMANCE_MODE_POWER_SAVING` 2. `AAUDIO_PERFORMANCE_MODE_LOW_LATENCY` | Value obtained from FuzzedDataProvider |
| `allowedCapturePolicy` | 0. `AAUDIO_ALLOW_CAPTURE_BY_ALL` 1. `AAUDIO_ALLOW_CAPTURE_BY_SYSTEM` 2. `AAUDIO_ALLOW_CAPTURE_BY_NONE` | Value obtained from FuzzedDataProvider |
| `sessionId` | 0. `AAUDIO_SESSION_ID_NONE` 1. `AAUDIO_SESSION_ID_ALLOCATE` | Value obtained from FuzzedDataProvider |
| `framesPerDataCallback` | Any value of type `int32_t` | Value obtained from FuzzedDataProvider |
| `policy` | 0. `AAUDIO_POLICY_NEVER` 1. `AAUDIO_POLICY_AUTO` 2. `AAUDIO_POLICY_ALWAYS` | Value obtained from FuzzedDataProvider |

This also ensures that the plugin is always deterministic for any given input.

##### Maximize utilization of input data
The plugin feed the entire input data to the module.
This ensures that the plugins tolerates any kind of input (empty, huge,
malformed, etc) and doesn't `exit()` on any input and thereby increasing the
chance of identifying vulnerabilities.

## Build

This describes steps to build libaaudio_fuzzer binary.

### Android

#### Steps to build
Build the fuzzer
```
  $ mm -j$(nproc) libaaudio_fuzzer
```
### Steps to run

To run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/libaaudio_fuzzer/libaaudio_fuzzer
```

## References:
 * http://llvm.org/docs/LibFuzzer.html
 * https://github.com/google/oss-fuzz
