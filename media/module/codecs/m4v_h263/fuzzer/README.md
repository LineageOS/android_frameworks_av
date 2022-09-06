# Fuzzer for libstagefright_m4vh263dec decoder

## Plugin Design Considerations
The fuzzer plugin for MPEG4/H263 is designed based on the understanding of the
codec and tries to achieve the following:

##### Maximize code coverage
Dict files (dictionary files) are created for MPEG4 and H263 to ensure that the required start
bytes are present in every input file that goes to the fuzzer.
This ensures that decoder does not reject any input file in the first check

##### Maximize utilization of input data
The plugin feeds the entire input data to the codec using a loop.
 * If the decode operation was successful, the input is advanced by the number of bytes consumed
   in the decode call.
 * If the decode operation was un-successful, the input is advanced by 1 byte so that the fuzzer
   can proceed to feed the next frame.

This ensures that the plugin tolerates any kind of input (empty, huge, malformed, etc)
and doesnt `exit()` on any input and thereby increasing the chance of identifying vulnerabilities.

##### Other considerations
 * Two fuzzer binaries - mpeg4_dec_fuzzer and h263_dec_fuzzer are generated based on the presence
   of a flag - 'MPEG4'
 * The number of decode calls are kept to a maximum of 100 so that the fuzzer does not timeout.

## Build

This describes steps to build mpeg4_dec_fuzzer and h263_dec_fuzzer binary.

### Android
#### Steps to build
Build the fuzzer
```
  $ mm -j$(nproc) mpeg4_dec_fuzzer
  $ mm -j$(nproc) h263_dec_fuzzer
```

#### Steps to run
Create a directory CORPUS_DIR and copy some MPEG4 or H263 files to that folder
Push this directory to device.

To run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/mpeg4_dec_fuzzer/mpeg4_dec_fuzzer CORPUS_DIR
  $ adb shell /data/fuzz/arm64/h263_dec_fuzzer/h263_dec_fuzzer CORPUS_DIR
```
To run on host
```
  $ $ANDROID_HOST_OUT/fuzz/x86_64/mpeg4_dec_fuzzer/mpeg4_dec_fuzzer CORPUS_DIR
  $ $ANDROID_HOST_OUT/fuzz/x86_64/h263_dec_fuzzer/h263_dec_fuzzer CORPUS_DIR
```

# Fuzzer for libstagefright_m4vh263enc encoder

## Plugin Design Considerations
The fuzzer plugin for MPEG4/H263 is designed based on the understanding of the
codec and tries to achieve the following:

##### Maximize code coverage
The configuration parameters are not hardcoded, but instead selected based on
incoming data. This ensures more code paths are reached by the fuzzer.

MPEG4/H263 supports the following parameters:
1. Frame Width (parameter name: `encWidth`)
2. Frame Height (parameter name: `encHeight`)
3. Rate control mode (parameter name: `rcType`)
4. Number of bytes per packet (parameter name: `packetSize`)
5. Qp for I-Vop(parameter name: `iQuant`)
6. Qp for P-Vop (parameter name: `pQuant`)
7. Enable RVLC mode (parameter name: `rvlcEnable`)
8. Quantization mode (parameter name: `quantType`)
9. Disable frame skipping (parameter name: `noFrameSkipped`)
10. Enable scene change detection (parameter name: `sceneDetect`)
11. Number of intra MBs in P-frame(parameter name: `numIntraMB`)
12. Search range of ME (parameter name: `searchRange`)
13. Enable 8x8 ME and MC (parameter name: `mv8x8Enable`)
14. Enable AC prediction (parameter name: `useACPred`)
15. Threshold for intra DC VLC (parameter name: `intraDCVlcTh`)
16. Encoding Mode (parameter name: `encMode`)

| Parameter| Valid Values| Configured Value|
|------------- |-------------| ----- |
| `rcType` | 0. `CONSTANT_Q` 1. `CBR_1` 2. `VBR_1` 3. `CBR_2` 4. `VBR_2` 5. `CBR_LOWDELAY` | All the bits of 6th byte of data modulus 6 |
| `packetSize` | In the range `0 to 255` | All the bits of 7th byte of data |
| `iQuant` | In the range `1 to 31` | All the bits of 8th byte of data |
| `pQuant` | In the range `1 to 31` | All the bits of 9th byte of data |
| `rvlcEnable` | 0. `PV_OFF` 1. `PV_ON` | bit 0 of 10th byte of data |
| `quantType` | 0. `0` 1. `1` | bit 0 of 11th byte of data |
| `noFrameSkipped` | 0. `PV_OFF` 1. `PV_ON` | bit 0 of 12th byte of data |
| `sceneDetect` | 0. `PV_OFF` 1. `PV_ON` | bit 0 of 13th byte of data |
| `numIntraMB` | In the range `0 to 7` | bit 0, 1 and 2 of 14th byte of data |
| `searchRange` | In the range `0 to 31` | bit 0, 1, 2, 3 and 4 of 15th byte of data |
| `mv8x8Enable` | 0. `PV_OFF` 1. `PV_ON` | bit 0 of 16th byte of data |
| `useACPred` | 0. `PV_OFF` 1. `PV_ON` | bit 0 of 17th byte of data |
| `intraDCVlcTh` | In the range `0 to 7` | bit 0, 1 and 2 of 18th byte of data |

Following parameters are only for mpeg4_enc_fuzzer

| Parameter| Valid Values| Configured Value|
|------------- |-------------| ----- |
| `encWidth` | In the range `0 to 10239` | All the bits of 1st and 2nd byte of data |
| `encHeight` | In the range `0 to 10239` | All the bits of 3rd and 4th byte of data |
| `encMode` | 0. `H263_MODE` 1. `H263_MODE_WITH_ERR_RES` 2. `DATA_PARTITIONING_MODE` 3. `COMBINE_MODE_NO_ERR_RES` 4. `COMBINE_MODE_WITH_ERR_RES` | All the bits of 19th byte of data modulus 5 |

Following parameters are only for h263_enc_fuzzer

| Parameter| Valid Values| Configured Value|
|------------- |-------------| ----- |
| `encWidth` | 0. `128` 1. `176` 2. `352` 3. `704` 4. `1408` | All the bits of 1st byte of data modulus 5|
| `encHeight` | 0. `96` 1. `144` 2. `288` 3. `576` 4. `1152 ` | All the bits of 3rd byte of data modulus 5|
| `encMode` | 0. `SHORT_HEADER` 1. `SHORT_HEADER_WITH_ERR_RES` | All the bits of 19th byte of data modulus 2 |

This also ensures that the plugin is always deterministic for any given input.

##### Maximize utilization of input data
The plugin feeds the entire input data to the codec using a loop.
If the encode operation was successful, the input is advanced by the frame size.
If the encode operation was un-successful, the input is still advanced by frame size so
that the fuzzer can proceed to feed the next frame.

This ensures that the plugin tolerates any kind of input (empty, huge,
malformed, etc) and doesnt `exit()` on any input and thereby increasing the
chance of identifying vulnerabilities.

## Build

This describes steps to build mpeg4_enc_fuzzer and h263_enc_fuzzer binary.

### Android

#### Steps to build
Build the fuzzer
```
  $ mm -j$(nproc) mpeg4_enc_fuzzer
  $ mm -j$(nproc) h263_enc_fuzzer
```

#### Steps to run
Create a directory CORPUS_DIR and copy some yuv files to that folder
Push this directory to device.

To run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/m4v_h263_enc_fuzzer/m4v_h263_enc_fuzzer CORPUS_DIR
  $ adb shell /data/fuzz/arm64/h263_enc_fuzzer/h263_enc_fuzzer CORPUS_DIR
```
To run on host
```
  $ $ANDROID_HOST_OUT/fuzz/x86_64/mpeg4_enc_fuzzer/mpeg4_enc_fuzzer CORPUS_DIR
  $ $ANDROID_HOST_OUT/fuzz/x86_64/h263_enc_fuzzer/h263_enc_fuzzer CORPUS_DIR
```

## References:
 * http://llvm.org/docs/LibFuzzer.html
 * https://github.com/google/oss-fuzz
