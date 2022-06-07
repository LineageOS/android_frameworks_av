# Fuzzers for libmediandk

## Table of contents
+ [ndk_crypto_fuzzer](#NdkCrypto)

# <a name="NdkCrypto"></a> Fuzzer for NdkCrypto

NdkCrypto supports the following parameters:
    UniversalIdentifier (parameter name: "uuid")

| Parameter| Valid Values |Configured Value|
|-------------|----------|----- |
| `uuid`| `Array`| Value obtained from FuzzedDataProvider|

#### Steps to run
1. Build the fuzzer
```
  $ mm -j$(nproc) ndk_crypto_fuzzer
```
2. Run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/ndk_crypto_fuzzer/ndk_crypto_fuzzer
```
