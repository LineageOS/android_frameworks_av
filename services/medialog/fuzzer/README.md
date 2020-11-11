# Fuzzer for libmedialogservice

## Plugin Design Considerations
The fuzzer plugin for libmedialogservice is designed based on the understanding of the
service and tries to achieve the following:

##### Maximize code coverage
The configuration parameters are not hardcoded, but instead selected based on
incoming data. This ensures more code paths are reached by the fuzzer.

medialogservice supports the following parameters:
1. Writer name (parameter name: `writerNameIdx`)
2. Log size (parameter name: `logSize`)
3. Enable dump before unrgister API (parameter name: `shouldDumpBeforeUnregister`)
5. size of string for log dump (parameter name: `numberOfLines`)

| Parameter| Valid Values| Configured Value|
|------------- |-------------| ----- |
| `writerNameIdx` | 0. `0` 1. `1` | Value obtained from FuzzedDataProvider |
| `logSize` | In the range `256 to 65536` | Value obtained from FuzzedDataProvider |
| `shouldDumpBeforeUnregister` | 0. `0` 1. `1` | Value obtained from FuzzedDataProvider |
| `numberOfLines` | In the range `0 to 65535` | Value obtained from FuzzedDataProvider |

This also ensures that the plugin is always deterministic for any given input.

## Build

This describes steps to build media_log_fuzzer binary.

### Android

#### Steps to build
Build the fuzzer
```
  $ mm -j$(nproc) media_log_fuzzer
```

#### Steps to run
Create a directory CORPUS_DIR and copy some files to that folder
Push this directory to device.

To run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/media_log_fuzzer/media_log_fuzzer CORPUS_DIR
```

## References:
 * http://llvm.org/docs/LibFuzzer.html
 * https://github.com/google/oss-fuzz
