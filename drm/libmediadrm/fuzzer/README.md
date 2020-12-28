# Fuzzer for libmediadrm

## Plugin Design Considerations
The fuzzer plugin for libmediadrm is designed based on the understanding of the
library and tries to achieve the following:

##### Maximize code coverage
The configuration parameters are not hardcoded, but instead selected based on
incoming data. This ensures more code paths are reached by the fuzzer.

libmediadrm supports the following parameters:
1. Security Level (parameter name: `securityLevel`)
2. Mime Type (parameter name: `mimeType`)
3. Key Type (parameter name: `keyType`)
4. Crypto Mode (parameter name: `cryptoMode`)

| Parameter| Valid Values| Configured Value|
|------------- |-------------| ----- |
| `securityLevel` | 0.`DrmPlugin::kSecurityLevelUnknown` 1.`DrmPlugin::kSecurityLevelMax` 2.`DrmPlugin::kSecurityLevelSwSecureCrypto` 3.`DrmPlugin::kSecurityLevelSwSecureDecode`  4.`DrmPlugin::kSecurityLevelHwSecureCrypto` 5.`DrmPlugin::kSecurityLevelHwSecureDecode` 6.`DrmPlugin::kSecurityLevelHwSecureAll`| Value obtained from FuzzedDataProvider in the range 0 to 6|
| `mimeType` | 0.`video/mp4` 1.`video/mpeg` 2.`video/x-flv` 3.`video/mj2` 4.`video/3gp2` 5.`video/3gpp` 6.`video/3gpp2` 7.`audio/mp4` 8.`audio/mpeg` 9.`audio/aac` 10.`audio/3gp2` 11.`audio/3gpp` 12.`audio/3gpp2` 13.`video/unknown`| Value obtained from FuzzedDataProvider in the range 0 to 13|
| `keyType` | 0.`DrmPlugin::kKeyType_Offline` 1.`DrmPlugin::kKeyType_Streaming` 2.`DrmPlugin::kKeyType_Release` | Value obtained from FuzzedDataProvider in the range 0 to 2|
| `cryptoMode` | 0.`CryptoPlugin::kMode_Unencrypted` 1.`CryptoPlugin::kMode_AES_CTR` 2.`CryptoPlugin::kMode_AES_WV` 3.`CryptoPlugin::kMode_AES_CBC` | Value obtained from FuzzedDataProvider in the range 0 to 3|

This also ensures that the plugin is always deterministic for any given input.

##### Maximize utilization of input data
The plugin feeds the entire input data to the drm module.
This ensures that the plugin tolerates any kind of input (empty, huge,
malformed, etc) and doesnt `exit()` on any input and thereby increasing the
chance of identifying vulnerabilities.

## Build

This describes steps to build mediadrm_fuzzer binary.

### Android

#### Steps to build
Build the fuzzer
```
  $ mm -j$(nproc) mediadrm_fuzzer
```
#### Steps to run
Create a directory CORPUS_DIR
```
  $ adb shell mkdir CORPUS_DIR
```
To run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/${TARGET_ARCH}/mediadrm_fuzzer/mediadrm_fuzzer CORPUS_DIR
```

## References:
 * http://llvm.org/docs/LibFuzzer.html
 * https://github.com/google/oss-fuzz
