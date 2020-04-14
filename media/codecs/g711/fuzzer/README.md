# Fuzzer for libstagefright_g711dec decoder

## Plugin Design Considerations
The fuzzer plugin for G711 is designed based on the understanding of the
codec and tries to achieve the following:

##### Maximize code coverage
G711 supports two types of decoding:
1. DecodeALaw
2. DecodeMLaw

These two decoder API's are fuzzed separately using g711alaw_dec_fuzzer and
g711mlaw_dec_fuzzer respectively.

##### Maximize utilization of input data
The plugin feeds the entire input data to the codec as expected by decoder API.

## Build

This describes steps to build g711alaw_dec_fuzzer and g711mlaw_dec_fuzzer binary.

### Android

#### Steps to build
Build the fuzzer
```
  $ mm -j$(nproc) g711alaw_dec_fuzzer
  $ mm -j$(nproc) g711mlaw_dec_fuzzer
```

#### Steps to run
Create a directory CORPUS_DIR and copy some g711 files to that folder
Push this directory to device.

To run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/g711alaw_dec_fuzzer/g711alaw_dec_fuzzer CORPUS_DIR
  $ adb shell /data/fuzz/arm64/g711mlaw_dec_fuzzer/g711mlaw_dec_fuzzer CORPUS_DIR
```
To run on host
```
  $ $ANDROID_HOST_OUT/fuzz/x86_64/g711alaw_dec_fuzzer/g711alaw_dec_fuzzer CORPUS_DIR
  $ $ANDROID_HOST_OUT/fuzz/x86_64/g711mlaw_dec_fuzzer/g711mlaw_dec_fuzzer CORPUS_DIR
```

## References:
 * http://llvm.org/docs/LibFuzzer.html
 * https://github.com/google/oss-fuzz
