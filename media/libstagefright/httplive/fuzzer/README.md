# Fuzzer for libstagefright_httplive

## Plugin Design Considerations
The fuzzer plugin for libstagefright_httplive is designed based on the understanding of the library and tries to achieve the following:

##### Maximize code coverage
The configuration parameters are not hardcoded, but instead selected based on
incoming data.Also, several .m3u8 files are hand-crafted and added to the corpus directory to increase the code coverage. This ensures more code paths are reached by the fuzzer.

libstagefright_httplive supports the following parameters:
1. Final Result (parameter name: `finalResult`)
2. Flags (parameter name: `flags`)
3. Time Us (parameter name: `timeUs`)
4. Track Index (parameter name: `trackIndex`)
5. Index (parameter name: `index`)
6. Select (parameter name: `select`)

| Parameter| Valid Values| Configured Value|
|------------- |-------------| ----- |
| `finalResult` | `-34` to `-1` | Value obtained from FuzzedDataProvider|
| `flags` | `0` to `1` | Value obtained from FuzzedDataProvider|
| `timeUs` | `0` to `10000000` | Value obtained from FuzzedDataProvider|
| `trackIndex` | `UINT32_MIN` to `UINT32_MAX` | Value obtained from FuzzedDataProvider|
| `index` | `UINT32_MIN` to `UINT32_MAX` | Value obtained from FuzzedDataProvider|
| `select` | `True` to `False` | Value obtained from FuzzedDataProvider|

This also ensures that the plugin is always deterministic for any given input.

##### Maximize utilization of input data
The plugin feeds the entire input data to the httplive module.
This ensures that the plugin tolerates any kind of input (empty, huge,
malformed, etc) and doesnt `exit()` on any input and thereby increasing the
chance of identifying vulnerabilities.

## Build

This describes steps to build httplive_fuzzer binary.

### Android

#### Steps to build
Build the fuzzer
```
  $ mm -j$(nproc) httplive_fuzzer
```
#### Steps to run
To run on device
```
  $ adb push $ANDROID_PRODUCT_OUT/data/fuzz/$(TARGET_ARCH)/lib /data/fuzz/$(TARGET_ARCH)/lib
  $ adb push $ANDROID_PRODUCT_OUT/data/fuzz/$(TARGET_ARCH)/httplive_fuzzer /data/fuzz/$(TARGET_ARCH)/httplive_fuzzer
  $ adb shell /data/fuzz/${TARGET_ARCH}/httplive_fuzzer/httplive_fuzzer /data/fuzz/${TARGET_ARCH}/httplive_fuzzer/corpus
```

## References:
 * http://llvm.org/docs/LibFuzzer.html
 * https://github.com/google/oss-fuzz
