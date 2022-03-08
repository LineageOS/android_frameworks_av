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
7. ChannelMask
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
| `ChannelMask` | `AAUDIO_UNSPECIFIED`, `AAUDIO_CHANNEL_INDEX_MASK_1`, `AAUDIO_CHANNEL_INDEX_MASK_2`, `AAUDIO_CHANNEL_INDEX_MASK_3`, `AAUDIO_CHANNEL_INDEX_MASK_4`, `AAUDIO_CHANNEL_INDEX_MASK_5`, `AAUDIO_CHANNEL_INDEX_MASK_6`, `AAUDIO_CHANNEL_INDEX_MASK_7`, `AAUDIO_CHANNEL_INDEX_MASK_8`, `AAUDIO_CHANNEL_INDEX_MASK_9`, `AAUDIO_CHANNEL_INDEX_MASK_10`, `AAUDIO_CHANNEL_INDEX_MASK_11`, `AAUDIO_CHANNEL_INDEX_MASK_12`, `AAUDIO_CHANNEL_INDEX_MASK_13`, `AAUDIO_CHANNEL_INDEX_MASK_14`, `AAUDIO_CHANNEL_INDEX_MASK_15`, `AAUDIO_CHANNEL_INDEX_MASK_16`, `AAUDIO_CHANNEL_INDEX_MASK_17`, `AAUDIO_CHANNEL_INDEX_MASK_18`, `AAUDIO_CHANNEL_INDEX_MASK_19`, `AAUDIO_CHANNEL_INDEX_MASK_20`, `AAUDIO_CHANNEL_INDEX_MASK_21`, `AAUDIO_CHANNEL_INDEX_MASK_22`, `AAUDIO_CHANNEL_INDEX_MASK_23`, `AAUDIO_CHANNEL_INDEX_MASK_24`, `AAUDIO_CHANNEL_MONO`, `AAUDIO_CHANNEL_STEREO`, `AAUDIO_CHANNEL_FRONT_BACK`, `AAUDIO_CHANNEL_2POINT0POINT2`, `AAUDIO_CHANNEL_2POINT1POINT2`, `AAUDIO_CHANNEL_3POINT0POINT2`, `AAUDIO_CHANNEL_3POINT1POINT2`, `AAUDIO_CHANNEL_5POINT1`, `AAUDIO_CHANNEL_MONO`, `AAUDIO_CHANNEL_STEREO`, `AAUDIO_CHANNEL_2POINT1`, `AAUDIO_CHANNEL_TRI`, `AAUDIO_CHANNEL_TRI_BACK`, `AAUDIO_CHANNEL_3POINT1`, `AAUDIO_CHANNEL_2POINT0POINT2`, `AAUDIO_CHANNEL_2POINT1POINT2`, `AAUDIO_CHANNEL_3POINT0POINT2`, `AAUDIO_CHANNEL_3POINT1POINT2`, `AAUDIO_CHANNEL_QUAD`, `AAUDIO_CHANNEL_QUAD_SIDE`, `AAUDIO_CHANNEL_SURROUND`, `AAUDIO_CHANNEL_PENTA`, `AAUDIO_CHANNEL_5POINT1`, `AAUDIO_CHANNEL_5POINT1_SIDE`, `AAUDIO_CHANNEL_5POINT1POINT2`, `AAUDIO_CHANNEL_5POINT1POINT4`, `AAUDIO_CHANNEL_6POINT1`, `AAUDIO_CHANNEL_7POINT1`, `AAUDIO_CHANNEL_7POINT1POINT2`, `AAUDIO_CHANNEL_7POINT1POINT4`, `AAUDIO_CHANNEL_9POINT1POINT4`, `AAUDIO_CHANNEL_9POINT1POINT6` | Value obtained from FuzzedDataProvider |
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
