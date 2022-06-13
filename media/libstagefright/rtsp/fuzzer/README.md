# Fuzzers for libstagefright_rtsp

## Table of contents
+ [sdploader_fuzzer](#SDPLoader)

# <a name="SDPLoader"></a> Fuzzer for SDPLoader

SDPLoader supports the following parameters:
1. Flag (parameter name: "flags")
2. URL (parameter name: "url")
3. Header (parameter name: "headers")

| Parameter| Valid Values| Configured Value|
|------------- |-------------| ----- |
|`flags`| `UINT32_MIN`  to  `UINT32_MAX` |Value obtained from FuzzedDataProvider|
|`url`| `String` |Value obtained from FuzzedDataProvider|
|`headers`| `String` |Value obtained from FuzzedDataProvider|

#### Steps to run
1. Build the fuzzer
```
  $ mm -j$(nproc) sdploader_fuzzer
```
2. Run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/sdploader_fuzzer/sdploader_fuzzer
```
