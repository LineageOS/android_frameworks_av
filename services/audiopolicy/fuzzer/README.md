# Fuzzer for libaudiopolicy

## Plugin Design Considerations
The fuzzer plugin for libaudiopolicy is designed based on the
understanding of the service and tries to achieve the following:

##### Maximize code coverage
The configuration parameters are not hardcoded, but instead selected based on
incoming data. This ensures more code paths are reached by the fuzzer.

AudioPolicy APIs contain the following parameters:
1. AudioFormats
2. AudioChannelMasks
3. AudioOutputFlags
4. AudioDevices
5. MixTypes
6. MixRouteFlags
7. SampleRates
8. AudioUsages
9. AudioContentTypes
10. AudioSources
11. AudioFlagMasks
12. AudioPolicyDeviceStates

| Parameter| Valid Input Values| Configured Value|
|------------- |-------------| ----- |
| `AudioFormat` | 77 values of type `audio_format_t` | Value chosen from valid values by obtaining index from FuzzedDataProvider |
| `AudioChannelMask` | 83 values of type `audio_channel_mask_t` | Value chosen from valid values by obtaining index from FuzzedDataProvider |
| `AudioOutputFlag` | 16 values of type `audio_output_flags_t` | Value chosen from valid values by obtaining index from FuzzedDataProvider |
| `AudioDevice`   | `AUDIO_DEVICE_OUT_AUX_DIGITAL`, `AUDIO_DEVICE_OUT_STUB`, `AUDIO_DEVICE_IN_VOICE_CALL`, `AUDIO_DEVICE_IN_AUX_DIGITAL`, `AUDIO_DEVICE_IN_STUB` | Value chosen from valid values by obtaining index from FuzzedDataProvider |
| `MixType`   | `MIX_TYPE_PLAYERS`, `MIX_TYPE_RECORDERS` | Value chosen from valid values by obtaining index from FuzzedDataProvider |
| `MixRouteFlag`   | `MIX_ROUTE_FLAG_RENDER`, `MIX_ROUTE_FLAG_LOOP_BACK`, `MIX_ROUTE_FLAG_LOOP_BACK_AND_RENDER`, `MIX_ROUTE_FLAG_ALL` | Value chosen from valid values by obtaining index from FuzzedDataProvider |
| `SampleRate` | `0` to `UINT32_MAX` | Value obtained from FuzzedDataProvider |
| `AudioUsage` | `AUDIO_USAGE_NOTIFICATION_COMMUNICATION_REQUEST`, `AUDIO_USAGE_NOTIFICATION_COMMUNICATION_INSTANT`, `AUDIO_USAGE_NOTIFICATION_COMMUNICATION_DELAYED`, `AUDIO_USAGE_NOTIFICATION_EVENT` | Value chosen from valid values by obtaining index from FuzzedDataProvider |
| `AudioContentType` | `AUDIO_CONTENT_TYPE_UNKNOWN`, `AUDIO_CONTENT_TYPE_SPEECH`, `AUDIO_CONTENT_TYPE_MUSIC`, `AUDIO_CONTENT_TYPE_MOVIE`, `AUDIO_CONTENT_TYPE_SONIFICATION` | Value chosen from valid values by obtaining index from FuzzedDataProvider |
| `AudioSource` | 14 values of type `audio_source_t` | Value chosen from valid values by obtaining index from FuzzedDataProvider |
| `AudioFlagMask` | 15 values of type `audio_flags_mask_t` | Value chosen from valid values by obtaining index from FuzzedDataProvider |
| `AudioPolicyDeviceStates` | `AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE`, `AUDIO_POLICY_DEVICE_STATE_AVAILABLE`, `AUDIO_POLICY_DEVICE_STATE_CNT` | Value chosen from valid values by obtaining index from FuzzedDataProvider |

This also ensures that the plugin is always deterministic for any given input.

## Build

This describes steps to build audiopolicy_fuzzer binary.

### Android

#### Steps to build
Build the fuzzer
```
  $ mm -j$(nproc) audiopolicy_fuzzer
```

#### Steps to run
To run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/audiopolicy_fuzzer/audiopolicy_fuzzer
```

## References:
 * http://llvm.org/docs/LibFuzzer.html
 * https://github.com/google/oss-fuzz
