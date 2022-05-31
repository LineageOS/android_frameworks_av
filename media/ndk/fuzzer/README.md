# Fuzzers for libmediandk

## Table of contents
+ [ndk_crypto_fuzzer](#NdkCrypto)
+ [ndk_image_reader_fuzzer](#NdkImageReader)
+ [ndk_extractor_fuzzer](#NdkExtractor)

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

# <a name="NdkImageReader"></a> Fuzzer for NdkImageReader

NdkImageReader supports the following parameters:
1. Width (parameter name: "imageWidth")
2. Height (parameter name: "imageHeight")
3. Format (parameter name: "imageFormat")
4. Usage (parameter name: "imageUsage")
5. Max images (parameter name: "imageMaxCount")

| Parameter| Valid Values |Configured Value|
|-------------|----------|----- |
| `width`| `1 to INT_MAX`| Value obtained from FuzzedDataProvider|
| `height`| `1 to INT_MAX`| Value obtained from FuzzedDataProvider|
| `format`| `1 to INT_MAX`| Value obtained from FuzzedDataProvider|
| `usage`| `1 to INT_MAX`| Value obtained from FuzzedDataProvider|
| `maxImages`| `1 to android::BufferQueue::MAX_MAX_ACQUIRED_BUFFERS`| Value obtained from FuzzedDataProvider|

#### Steps to run
1. Build the fuzzer
```
  $ mm -j$(nproc) ndk_image_reader_fuzzer
```
2. Run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/ndk_image_reader_fuzzer/ndk_image_reader_fuzzer
```

# <a name="NdkExtractor"></a>Fuzzer for NdkExtractor

NdkExtractor supports the following parameters:
1. SeekMode (parameter name: "mode")

| Parameter| Valid Values |Configured Value|
|-------------|----------|----- |
|`mode`|0.`AMEDIAEXTRACTOR_SEEK_PREVIOUS_SYNC`,<br/>1.`AMEDIAEXTRACTOR_SEEK_NEXT_SYNC`,<br/>2.`AMEDIAEXTRACTOR_SEEK_CLOSEST_SYNC`| Value obtained from FuzzedDataProvider|

#### Steps to run
1. Build the fuzzer
```
  $ mm -j$(nproc) ndk_extractor_fuzzer
```
2. Run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/ndk_extractor_fuzzer/ndk_extractor_fuzzer /data/fuzz/${TARGET_ARCH}/ndk_extractor_fuzzer/corpus
```
