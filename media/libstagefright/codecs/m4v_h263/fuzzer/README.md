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

## References:
 * http://llvm.org/docs/LibFuzzer.html
 * https://github.com/google/oss-fuzz
