# Fuzzer for libstagefright_amrnbenc encoder

## Plugin Design Considerations
The fuzzer plugin for AMR-NB is designed based on the understanding of the
codec and tries to achieve the following:

##### Maximize code coverage
The configuration parameters are not hardcoded, but instead selected based on
incoming data. This ensures more code paths are reached by the fuzzer.

AMR-WB supports the following parameters:
1. Output Format (parameter name: `outputFormat`)
2. Mode (parameter name: `mode`)

| Parameter| Valid Values| Configured Value|
|------------- |-------------| ----- |
| `outputFormat` | 0. `AMR_TX_WMF` 1. `AMR_TX_IF2` 2. `AMR_TX_ETS` | Bits 0, 1 and 2 of 1st byte of data. |
| `mode`   | 0. `MR475` 1. `MR515` 2. `MR59` 3. `MR67`  4. `MR74 ` 5. `MR795` 6. `MR102` 7. `MR122` 8. `MRDTX` | Bits 3, 4, 5 and 6 of 1st byte of data. |

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

This describes steps to build amrnb_enc_fuzzer binary.

### Android

#### Steps to build
Build the fuzzer
```
  $ mm -j$(nproc) amrnb_enc_fuzzer
```

#### Steps to run
Create a directory CORPUS_DIR and copy some pcm files to that folder
Push this directory to device.

To run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/amrnb_enc_fuzzer/amrnb_enc_fuzzer CORPUS_DIR
```
To run on host
```
  $ $ANDROID_HOST_OUT/fuzz/x86_64/amrnb_enc_fuzzer/amrnb_enc_fuzzer CORPUS_DIR
```

## References:
 * http://llvm.org/docs/LibFuzzer.html
 * https://github.com/google/oss-fuzz
