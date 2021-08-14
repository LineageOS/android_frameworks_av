# Fuzzer for libaaudioservice

## Plugin Design Considerations
The fuzzer plugin for libaaudioservice is designed based on the
understanding of the service and tries to achieve the following:

##### Maximize code coverage
The configuration parameters are not hardcoded, but instead selected based on
incoming data. This ensures more code paths are reached by the fuzzer.

AAudio Service request contains the following parameters:
1. AAudioFormat
2. UserId
3. ProcessId
4. InService
5. DeviceId
6. SampleRate
7. SamplesPerFrame
8. Direction
9. SharingMode
10. Usage
11. ContentType
12. InputPreset
13. BufferCapacity

| Parameter| Valid Input Values| Configured Value|
|------------- |-------------| ----- |
| `AAudioFormat` | `AAUDIO_FORMAT_UNSPECIFIED`, `AAUDIO_FORMAT_PCM_I16`, `AAUDIO_FORMAT_PCM_FLOAT` | Value chosen from valid values by obtaining index from FuzzedDataProvider |
| `UserId`   | `INT32_MIN` to `INT32_MAX` | Value obtained from getuid() |
| `ProcessId`   | `INT32_MIN` to `INT32_MAX` | Value obtained from getpid() |
| `InService`   | `bool` | Value obtained from FuzzedDataProvider |
| `DeviceId`   | `INT32_MIN` to `INT32_MAX` | Value obtained from FuzzedDataProvider |
| `SampleRate`   | `INT32_MIN` to `INT32_MAX` | Value obtained from FuzzedDataProvider |
| `SamplesPerFrame` | `INT32_MIN` to `INT32_MAX` | Value obtained from FuzzedDataProvider |
| `Direction` | `AAUDIO_DIRECTION_OUTPUT`, `AAUDIO_DIRECTION_INPUT` | Value chosen from valid values by obtaining index from FuzzedDataProvider |
| `SharingMode` | `AAUDIO_SHARING_MODE_EXCLUSIVE`, `AAUDIO_SHARING_MODE_SHARED` | Value chosen from valid values by obtaining index from FuzzedDataProvider |
| `Usage` | `AAUDIO_USAGE_MEDIA`, `AAUDIO_USAGE_VOICE_COMMUNICATION`, `AAUDIO_USAGE_VOICE_COMMUNICATION_SIGNALLING`, `AAUDIO_USAGE_ALARM`, `AAUDIO_USAGE_NOTIFICATION`, `AAUDIO_USAGE_NOTIFICATION_RINGTONE`, `AAUDIO_USAGE_NOTIFICATION_EVENT`, `AAUDIO_USAGE_ASSISTANCE_ACCESSIBILITY`, `AAUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE`, `AAUDIO_USAGE_ASSISTANCE_SONIFICATION`, `AAUDIO_USAGE_GAME`, `AAUDIO_USAGE_ASSISTANT`, `AAUDIO_SYSTEM_USAGE_EMERGENCY`, `AAUDIO_SYSTEM_USAGE_SAFETY`, `AAUDIO_SYSTEM_USAGE_VEHICLE_STATUS`, `AAUDIO_SYSTEM_USAGE_ANNOUNCEMENT` | Value chosen from valid values by obtaining index from FuzzedDataProvider |
| `ContentType` | `AAUDIO_CONTENT_TYPE_SPEECH`, `AAUDIO_CONTENT_TYPE_MUSIC`, `AAUDIO_CONTENT_TYPE_MOVIE`, `AAUDIO_CONTENT_TYPE_SONIFICATION` | Value chosen from valid values by obtaining index from FuzzedDataProvider |
| `InputPreset` | `AAUDIO_INPUT_PRESET_GENERIC`, `AAUDIO_INPUT_PRESET_CAMCORDER`, `AAUDIO_INPUT_PRESET_VOICE_RECOGNITION`, `AAUDIO_INPUT_PRESET_VOICE_COMMUNICATION`, `AAUDIO_INPUT_PRESET_UNPROCESSED`, `AAUDIO_INPUT_PRESET_VOICE_PERFORMANCE` | Value chosen from valid values by obtaining index from FuzzedDataProvider |
| `BufferCapacity` | `INT32_MIN` to `INT32_MAX` | Value obtained from FuzzedDataProvider |

This also ensures that the plugin is always deterministic for any given input.

## Build

This describes steps to build oboeservice_fuzzer binary.

### Android

#### Steps to build
Build the fuzzer
```
  $ mm -j$(nproc) oboeservice_fuzzer
```

#### Steps to run
To run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/oboeservice_fuzzer/oboeservice_fuzzer
```

## References:
 * http://llvm.org/docs/LibFuzzer.html
 * https://github.com/google/oss-fuzz
