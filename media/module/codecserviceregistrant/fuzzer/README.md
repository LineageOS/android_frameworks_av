# Fuzzer for libmedia_codecserviceregistrant

## Plugin Design Considerations
The fuzzer plugin for libmedia_codecserviceregistrant is designed based on the understanding of the library and tries to achieve the following:

##### Maximize code coverage
The configuration parameters are not hardcoded, but instead selected based on
incoming data. This ensures more code paths are reached by the fuzzer.

libmedia_codecserviceregistrant supports the following parameters:
1. C2String (parameter name: `c2String`)
2. Width (parameter name: `width`)
3. Height (parameter name: `height`)
4. SamplingRate (parameter name: `samplingRate`)
5. Channels (parameter name: `channels`)
6. Stream (parameter name: `stream`)

| Parameter| Valid Values| Configured Value|
|------------- |-------------| ----- |
| `c2String` |`String` | Value obtained from FuzzedDataProvider|
| `width` |`UINT32_MIN` to `UINT32_MAX` | Value obtained from FuzzedDataProvider|
| `height` |`UINT32_MIN` to `UINT32_MAX` | Value obtained from FuzzedDataProvider|
| `samplingRate` |`UINT32_MIN` to `UINT32_MAX` | Value obtained from FuzzedDataProvider|
| `channels` |`UINT32_MIN` to `UINT32_MAX` | Value obtained from FuzzedDataProvider|
| `stream` |`UINT32_MIN` to `UINT32_MAX` | Value obtained from FuzzedDataProvider|

This also ensures that the plugin is always deterministic for any given input.

##### Maximize utilization of input data
The plugin feeds the entire input data to the libmedia_codecserviceregistrant module.
This ensures that the plugin tolerates any kind of input (empty, huge,
malformed, etc) and doesnt `exit()` on any input and thereby increasing the
chance of identifying vulnerabilities.

## Build

This describes steps to build codecServiceRegistrant_fuzzer binary.

### Android

#### Steps to build
Build the fuzzer
```
  $ mm -j$(nproc) codecServiceRegistrant_fuzzer
```
#### Steps to run

To run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/${TARGET_ARCH}/codecServiceRegistrant_fuzzer/codecServiceRegistrant_fuzzer
```

## References:
 * http://llvm.org/docs/LibFuzzer.html
 * https://github.com/google/oss-fuzz
