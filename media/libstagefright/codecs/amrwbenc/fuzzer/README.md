# Fuzzer for libstagefright_amrwbenc encoder

## Plugin Design Considerations
The fuzzer plugin for AMR-WB is designed based on the understanding of the
codec and tries to achieve the following:

##### Maximize code coverage
The configuration parameters are not hardcoded, but instead selected based on
incoming data. This ensures more code paths are reached by the fuzzer.

AMR-WB supports the following parameters:
1. Frame Type (parameter name: `frameType`)
2. Mode (parameter name: `mode`)

| Parameter| Valid Values| Configured Value|
|------------- |-------------| ----- |
| `frameType` | 0. `VOAMRWB_DEFAULT` 1. `VOAMRWB_ITU` 2. `VOAMRWB_RFC3267` | Bits 0, 1 and 2 of 1st byte of data. |
| `mode`   | 0. `VOAMRWB_MD66` 1. `VOAMRWB_MD885` 2. `VOAMRWB_MD1265` 3. `VOAMRWB_MD1425`  4. `VOAMRWB_MD1585 ` 5. `VOAMRWB_MD1825` 6. `VOAMRWB_MD1985` 7. `VOAMRWB_MD2305` 8. `VOAMRWB_MD2385` 9. `VOAMRWB_N_MODES` | Bits 4, 5, 6 and 7 of 1st byte of data. |

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

This describes steps to build amrwb_enc_fuzzer binary.

### Android

#### Steps to build
Build the fuzzer
```
  $ mm -j$(nproc) amrwb_enc_fuzzer
```

#### Steps to run
Create a directory CORPUS_DIR and copy some pcm files to that folder
Push this directory to device.

To run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/amrwb_enc_fuzzer/amrwb_enc_fuzzer CORPUS_DIR
```
To run on host
```
  $ $ANDROID_HOST_OUT/fuzz/x86_64/amrwb_enc_fuzzer/amrwb_enc_fuzzer CORPUS_DIR
```

## References:
 * http://llvm.org/docs/LibFuzzer.html
 * https://github.com/google/oss-fuzz
