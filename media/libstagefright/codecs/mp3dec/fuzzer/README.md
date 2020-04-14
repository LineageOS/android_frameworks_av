# Fuzzer for libstagefright_mp3dec decoder

## Plugin Design Considerations
The fuzzer plugin for mp3 decoder is designed based on the understanding of the
codec and tries to achieve the following:

##### Maximize code coverage

This fuzzer makes use of the following config parameters:
1. Equalizer type (parameter name: `equalizerType`)

| Parameter| Valid Values| Configured Value|
|------------- |-------------| ----- |
| `equalizerType` | 0. `flat ` 1. `bass_boost ` 2. `rock ` 3. `pop ` 4. `jazz ` 5. `classical ` 6. `talk ` 7. `flat_ ` | Bits 0, 1 and 2 of first byte of input stream |
| `crcEnabled` | 0. `false ` 1. `true `| Bit 0 of second byte of input stream |

##### Maximize utilization of input data
The plugin feeds the entire input data to the codec using a loop.
 * If the decode operation was successful, the input is advanced by the number
   of bytes used by the decoder.
 * If the decode operation was un-successful, the input is advanced by 1 byte
   till it reaches a valid frame or end of stream.

This ensures that the plugin tolerates any kind of input (empty, huge,
malformed, etc) and doesnt `exit()` on any input and thereby increasing the
chance of identifying vulnerabilities.

## Build

This describes steps to build mp3_dec_fuzzer binary.

### Android

#### Steps to build
Build the fuzzer
```
  $ mm -j$(nproc) mp3_dec_fuzzer
```

#### Steps to run
Create a directory CORPUS_DIR and copy some mp3 files to that folder.
Push this directory to device.

To run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/mp3_dec_fuzzer/mp3_dec_fuzzer CORPUS_DIR
```
To run on host
```
  $ $ANDROID_HOST_OUT/fuzz/x86_64/mp3_dec_fuzzer/mp3_dec_fuzzer CORPUS_DIR
```

## References:
 * http://llvm.org/docs/LibFuzzer.html
 * https://github.com/google/oss-fuzz
