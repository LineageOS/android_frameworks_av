# Fuzzers for libmtp

## Table of contents
+ [mtp_fuzzer](#MtpServer)
+ [mtp_host_property_fuzzer](#MtpHostProperty)
+ [mtp_device_property_fuzzer](#MtpDeviceProperty)
+ [mtp_handle_fuzzer](#MtpHandle)
+ [mtp_packet_fuzzer](#MtpPacket)
 + [mtp_device_fuzzer](#MtpDevice)
+ [mtp_request_packet_fuzzer](#MtpRequestPacket)
+ [mtp_event_packet_fuzzer](#MtpEventPacket)
+ [mtp_response_packet_fuzzer](#MtpResponsePacket)
+ [mtp_data_packet_fuzzer](#MtpDataPacket)

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

# <a name="MtpHostProperty"></a> Fuzzer for MtpHostProperty

MtpHostProperty supports the following parameters:
1. Feasible Type (parameter name: "kFeasibleTypes")
2. UrbPacket Division Mode (parameter name: "kUrbPacketDivisionModes")

| Parameter| Valid Values |Configured Value|
|-------------|----------|----- |
| `kFeasibleType`| 1. `MTP_TYPE_UNDEFINED`, 2. `MTP_TYPE_INT8`, 3.`MTP_TYPE_UINT8`, 4.`MTP_TYPE_INT16`, 5.`MTP_TYPE_UINT16`, 6.`MTP_TYPE_INT32`, 7.`MTP_TYPE_UINT32`, 8.`MTP_TYPE_INT64`, 9.`MTP_TYPE_UINT64`, 10.`MTP_TYPE_INT128`, 11.`MTP_TYPE_UINT128`, 12.`MTP_TYPE_AINT8`, 13.`MTP_TYPE_AUINT8`, 14.`MTP_TYPE_AINT16`, 15.`MTP_TYPE_AUINT16`, 16.`MTP_TYPE_AINT32`, 17.`MTP_TYPE_AUINT32`, 18.`MTP_TYPE_AINT64`, 19.`MTP_TYPE_AUINT64`, 20.`MTP_TYPE_AINT128`, 21.`MTP_TYPE_AUINT128`, 22.`MTP_TYPE_STR`,| Value obtained from FuzzedDataProvider|
|`kUrbPacketDivisionMode`| 1. `FIRST_PACKET_ONLY_HEADER`, 2. `FIRST_PACKET_HAS_PAYLOAD`, |Value obtained from FuzzedDataProvider|

#### Steps to run
1. Build the fuzzer
```
  $ mm -j$(nproc) mtp_host_property_fuzzer
```
2. Run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/mtp_host_property_fuzzer/mtp_host_property_fuzzer
```

# <a name="MtpDeviceProperty"></a> Fuzzer for MtpDeviceProperty

MtpDeviceProperty supports the following parameters:
1. Feasible Type (parameter name: "kFeasibleType")

| Parameter| Valid Values |Configured Value|
|-------------|----------|----- |
| `kFeasibleType`| 1. `MTP_TYPE_UNDEFINED`, 2. `MTP_TYPE_INT8`, 3.`MTP_TYPE_UINT8`, 4.`MTP_TYPE_INT16`, 5.`MTP_TYPE_UINT16`, 6.`MTP_TYPE_INT32`, 7.`MTP_TYPE_UINT32`, 8.`MTP_TYPE_INT64`, 9.`MTP_TYPE_UINT64`, 10.`MTP_TYPE_INT128`, 11.`MTP_TYPE_UINT128`, 12.`MTP_TYPE_AINT8`, 13.`MTP_TYPE_AUINT8`, 14.`MTP_TYPE_AINT16`, 15.`MTP_TYPE_AUINT16`, 16.`MTP_TYPE_AINT32`, 17.`MTP_TYPE_AUINT32`, 18.`MTP_TYPE_AINT64`, 19.`MTP_TYPE_AUINT64`, 20.`MTP_TYPE_AINT128`, 21.`MTP_TYPE_AUINT128`, 22.`MTP_TYPE_STR`,| Value obtained from FuzzedDataProvider|

#### Steps to run
1. Build the fuzzer
```
  $ mm -j$(nproc) mtp_device_property_fuzzer
```
2. Run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/mtp_device_property_fuzzer/mtp_device_property_fuzzer
```

# <a name="MtpHandle"></a>Fuzzer for MtpHandle

#### Steps to run
1. Build the fuzzer
```
  $ mm -j$(nproc) mtp_handle_fuzzer
```
2. Run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/mtp_handle_fuzzer/mtp_handle_fuzzer
```

# <a name="MtpPacket"></a> Fuzzer for MtpPacket

MtpPacket supports the following parameters:
1. bufferSize (parameter name: "size")

| Parameter| Valid Values |Configured Value|
|-------------|----------|----- |
|`bufferSize`| Integer `1` to `1000`, |Value obtained from FuzzedDataProvider|

#### Steps to run
1. Build the fuzzer
```
  $ mm -j$(nproc) mtp_packet_fuzzer
```
2. Run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/mtp_packet_fuzzer/mtp_packet_fuzzer
```

# <a name="MtpDevice"></a> Fuzzer for MtpDevice

MtpDevice supports the following parameters:
1. Device Name (parameter name: "deviceName")

| Parameter| Valid Values |Configured Value|
|-------------|----------|----- |
|`deviceName`| `String` |Value obtained from FuzzedDataProvider|

#### Steps to run
1. Build the fuzzer
```
  $ mm -j$(nproc) mtp_device_fuzzer
```
2. Run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/mtp_device_fuzzer/mtp_device_fuzzer
```

# <a name="MtpRequestPacket"></a> Fuzzer for MtpRequestPacket

MtpRequestPacket supports the following parameters:
1. Data (parameter name: "data")

| Parameter| Valid Values |Configured Value|
|-------------|----------|----- |
|`data`| Vector of positive Integer |Value obtained from FuzzedDataProvider|

#### Steps to run
1. Build the fuzzer
```
  $ mm -j$(nproc) mtp_request_packet_fuzzer
```
2. Run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/mtp_request_packet_fuzzer/mtp_request_packet_fuzzer
```

# <a name="MtpEventPacket"></a> Fuzzer for MtpEventPacket

MtpEventPacket supports the following parameters:
1. Size (parameter name: "size")

| Parameter| Valid Values |Configured Value|
|-------------|----------|----- |
|`size`| Integer `1` to `1000`, |Value obtained from FuzzedDataProvider|

#### Steps to run
1. Build the fuzzer
```
  $ mm -j$(nproc) mtp_event_packet_fuzzer
```
2. Run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/mtp_event_packet_fuzzer/mtp_event_packet_fuzzer
```

# <a name="MtpResponsePacket"></a> Fuzzer for MtpResponsePacket

MtpResponsePacket supports the following parameters:
1. Size (parameter name: "size")

| Parameter| Valid Values |Configured Value|
|-------------|----------|----- |
|`size`| Integer `1` to `1000`, |Value obtained from FuzzedDataProvider|

#### Steps to run
1. Build the fuzzer
```
  $ mm -j$(nproc) mtp_response_packet_fuzzer
```
2. Run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/mtp_response_packet_fuzzer/mtp_response_packet_fuzzer
```

# <a name="MtpDataPacket"></a> Fuzzer for MtpDataPacket

MtpDataPacket supports the following parameters:
1. UrbPacket Division Mode (parameter name: "kUrbPacketDivisionModes")
2. Size (parameter name: "size")

| Parameter| Valid Values |Configured Value|
|-------------|----------|----- |
|`kUrbPacketDivisionMode`| 1. `FIRST_PACKET_ONLY_HEADER`, 2. `FIRST_PACKET_HAS_PAYLOAD`, |Value obtained from FuzzedDataProvider|
|`size`| Integer `1` to `1000`, |Value obtained from FuzzedDataProvider|

#### Steps to run
1. Build the fuzzer
```
  $ mm -j$(nproc) mtp_data_packet_fuzzer
```
2. Run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/mtp_data_packet_fuzzer/mtp_data_packet_fuzzer
```
