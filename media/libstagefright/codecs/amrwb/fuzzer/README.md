# Fuzzer for libstagefright_amrwbdec decoder

## Plugin Design Considerations
The fuzzer plugin for AMR-WB is designed based on the understanding of the
codec and tries to achieve the following:

##### Maximize code coverage
The configuration parameters are not hardcoded, but instead selected based on
incoming data. This ensures more code paths are reached by the fuzzer.

AMR-WB supports the following parameters:
1. Quality (parameter name: `quality`)
2. Mode (parameter name: `mode`)

| Parameter| Valid Values| Configured Value|
|------------- |-------------| ----- |
| `quality` | 0. `Bad Quality` 1. `Good quality` | Bit 0 (LSB) of 1st byte of data. |
| `mode`   | 0. `MODE_7k` 1. `MODE_9k` 2. `MODE_12k` 3. `MODE_14k`  4. `MODE_16k ` 5. `MODE_18k` 6. `MODE_20k` 7. `MODE_23k` 8. `MODE_24k` 9. `MRDTX`  | Bits 3, 4, 5 and 6 of 1st byte of data. |

This also ensures that the plugin is always deterministic for any given input.

##### Maximize utilization of input data
The plugin feeds the entire input data to the codec using a loop.
If the decode operation was successful, the input is advanced by the frame size
which is based on `mode` and `quality` selected.
If the decode operation was un-successful, the input is still advanced by frame size so
that the fuzzer can proceed to feed the next frame.

This ensures that the plugin tolerates any kind of input (empty, huge,
malformed, etc) and doesnt `exit()` on any input and thereby increasing the
chance of identifying vulnerabilities.

## Build

This describes steps to build amrwb_dec_fuzzer binary.

### Android

#### Steps to build
Build the fuzzer
```
  $ mm -j$(nproc) amrwb_dec_fuzzer
```

#### Steps to run
Create a directory CORPUS_DIR and copy some amrwb files to that folder
Push this directory to device.

To run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/amrwb_dec_fuzzer/amrwb_dec_fuzzer CORPUS_DIR
```
To run on host
```
  $ $ANDROID_HOST_OUT/fuzz/x86_64/amrwb_dec_fuzzer/amrwb_dec_fuzzer CORPUS_DIR
```

## References:
 * http://llvm.org/docs/LibFuzzer.html
 * https://github.com/google/oss-fuzz
