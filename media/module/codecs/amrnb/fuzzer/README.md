# Fuzzer for libstagefright_amrnbdec decoder

## Plugin Design Considerations
The fuzzer plugin for AMR-NB is designed based on the understanding of the
codec and tries to achieve the following:

##### Maximize code coverage
The configuration parameters are not hardcoded, but instead selected based on
incoming data. This ensures more code paths are reached by the fuzzer.

AMR-NB supports the following parameters:
1. Stream format (parameter name: `input_format`)
2. 3GPP frame type (parameter name: `frame_type`)

| Parameter| Valid Values| Configured Value|
|------------- |-------------| ----- |
| `input_format` | 0. `MIME_IETF` 1. `IF2` | Bit 0 (LSB) of 1st byte of data. |
| `frame_type`   | 0. `AMR_475` 1. `AMR_515` 2. `AMR_59` 3. `AMR_67`  4. `AMR_74` 5. `AMR_795` 6. `AMR_102` 7. `AMR_122`  | Bits 3, 4 and 5 of 1st byte of data. |


This also ensures that the plugin is always deterministic for any given input.

##### Maximize utilization of input data
The plugin feeds the entire input data to the codec using a loop.
If the decode operation was successful, the input is advanced by the frame size
which is based on `input_format` and `frame_type` selected.
If the decode operation was un-successful, the input is still advanced by frame size so
that the fuzzer can proceed to feed the next frame.

This ensures that the plugin tolerates any kind of input (empty, huge,
malformed, etc) and doesnt `exit()` on any input and thereby increasing the
chance of identifying vulnerabilities.

## Build

This describes steps to build amrnb_dec_fuzzer binary.

### Android

#### Steps to build
Build the fuzzer
```
  $ mm -j$(nproc) amrnb_dec_fuzzer
```

#### Steps to run
Create a directory CORPUS_DIR and copy some amrnb files to that folder
Push this directory to device.

To run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/amrnb_dec_fuzzer/amrnb_dec_fuzzer CORPUS_DIR
```
To run on host
```
  $ $ANDROID_HOST_OUT/fuzz/x86_64/amrnb_dec_fuzzer/amrnb_dec_fuzzer CORPUS_DIR
```

## References:
 * http://llvm.org/docs/LibFuzzer.html
 * https://github.com/google/oss-fuzz
