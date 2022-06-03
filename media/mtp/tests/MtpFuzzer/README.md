# Fuzzers for libmtp

## Table of contents
+ [mtp_fuzzer](#MtpServer)

# <a name="MtpServer"></a> Fuzzer for MtpServer

MtpServer supports the following parameters:
1. PacketData (parameter name: "packetData")

| Parameter| Valid Values |Configured Value|
|-------------|----------|----- |
|`packetData`| `String` |Value obtained from FuzzedDataProvider|

#### Steps to run
1. Build the fuzzer
```
  $ mm -j$(nproc) mtp_fuzzer
```
2. Run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/mtp_fuzzer/mtp_fuzzer corpus/ -dict=mtp_fuzzer.dict
```
