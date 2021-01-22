# Fuzzer for libresourcemanagerservice

## Plugin Design Considerations
The fuzzer plugin for libresourcemanagerservice is designed based on the
understanding of the service and tries to achieve the following:

##### Maximize code coverage
The configuration parameters are not hardcoded, but instead selected based on
incoming data. This ensures more code paths are reached by the fuzzer.

Media Resource Manager supports the following parameters:
1. Media Resource Type (parameter name: `mediaResourceType`)
2. Media Resource SubType (parameter name: `mediaResourceSubType`)

| Parameter| Valid Values| Configured Value|
|------------- |-------------| ----- |
| `mediaResourceType` | 0.`MediaResource::kSecureCodec` 1.`MediaResource::kNonSecureCodecC` 2.`MediaResource::kGraphicMemory` 3.`MediaResource::kCpuBoost`  4.`MediaResource::kBattery` 5.`MediaResource::kDrmSession`| Value obtained from FuzzedDataProvider |
| `mediaResourceSubType`   | 0.`MediaResource::kAudioCodec` 1.`MediaResource::kVideoCodec` 2.`MediaResource::kUnspecifiedSubType`  | Value obtained from FuzzedDataProvider |

This also ensures that the plugin is always deterministic for any given input.

## Build

This describes steps to build mediaresourcemanager_fuzzer binary.

### Android

#### Steps to build
Build the fuzzer
```
  $ mm -j$(nproc) mediaresourcemanager_fuzzer
```

#### Steps to run
Create a directory CORPUS_DIR and copy some files to that folder
Push this directory to device.

To run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/mediaresourcemanager_fuzzer/mediaresourcemanager_fuzzer CORPUS_DIR
```

## References:
 * http://llvm.org/docs/LibFuzzer.html
 * https://github.com/google/oss-fuzz
