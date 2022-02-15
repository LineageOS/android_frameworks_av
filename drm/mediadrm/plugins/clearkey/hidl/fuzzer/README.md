# Fuzzer for android.hardware.drm@1.4-service.clearkey

## Plugin Design Considerations
The fuzzer plugin for android.hardware.drm@1.4-service.clearkey is designed based on the understanding of the
source code and tries to achieve the following:

##### Maximize code coverage
The configuration parameters are not hardcoded, but instead selected based on
incoming data. This ensures more code paths are reached by the fuzzer.

android.hardware.drm@1.4-service.clearkey supports the following parameters:
1. Security Level (parameter name: `securityLevel`)
2. Mime Type (parameter name: `mimeType`)
3. Key Type (parameter name: `keyType`)
4. Crypto Mode (parameter name: `cryptoMode`)

| Parameter| Valid Values| Configured Value|
|------------- |-------------| ----- |
| `securityLevel` | 0.`SecurityLevel::UNKNOWN` 1.`SecurityLevel::SW_SECURE_CRYPTO` 2.`SecurityLevel::SW_SECURE_DECODE` 3.`SecurityLevel::HW_SECURE_CRYPTO`  4.`SecurityLevel::HW_SECURE_DECODE` 5.`SecurityLevel::HW_SECURE_ALL`| Value obtained from FuzzedDataProvider in the range 0 to 5|
| `mimeType` | 0.`video/mp4` 1.`video/mpeg` 2.`video/x-flv` 3.`video/mj2` 4.`video/3gp2` 5.`video/3gpp` 6.`video/3gpp2` 7.`audio/mp4` 8.`audio/mpeg` 9.`audio/aac` 10.`audio/3gp2` 11.`audio/3gpp` 12.`audio/3gpp2` 13.`audio/webm` 14.`video/webm` 15.`webm` 16.`cenc` 17.`video/unknown` 18.`audio/unknown`| Value obtained from FuzzedDataProvider in the range 0 to 18|
| `keyType` | 0.`KeyType::OFFLINE` 1.`KeyType::STREAMING` 2.`KeyType::RELEASE` | Value obtained from FuzzedDataProvider in the range 0 to 2|
| `cryptoMode` | 0.`Mode::UNENCRYPTED` 1.`Mode::AES_CTR` 2.`Mode::AES_CBC_CTS` 3.`Mode::AES_CBC` | Value obtained from FuzzedDataProvider in the range 0 to 3|

This also ensures that the plugin is always deterministic for any given input.

##### Maximize utilization of input data
The plugin feeds the entire input data to the module.
This ensures that the plugin tolerates any kind of input (empty, huge,
malformed, etc) and doesnt `exit()` on any input and thereby increasing the
chance of identifying vulnerabilities.

## Build

This describes steps to build clearkeyV1.4_fuzzer binary.

### Android

#### Steps to build
Build the fuzzer
```
  $ mm -j$(nproc) clearkeyV1.4_fuzzer
```
#### Steps to run
To run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/${TARGET_ARCH}/clearkeyV1.4_fuzzer/vendor/hw/clearkeyV1.4_fuzzer
```

## References:
 * http://llvm.org/docs/LibFuzzer.html
 * https://github.com/google/oss-fuzz
