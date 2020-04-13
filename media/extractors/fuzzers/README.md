# Fuzzer for extractors

## Table of contents
1. [libextractorfuzzerbase](#ExtractorFuzzerBase)
2. [libmp4extractor](#mp4ExtractorFuzzer)

# <a name="ExtractorFuzzerBase"></a> Fuzzer for libextractorfuzzerbase
All the extractors have a common API - creating a data source, extraction
of all the tracks, etc. These common APIs have been abstracted in a base class
called `ExtractorFuzzerBase` to ensure code is reused between fuzzer plugins.

Additionally, `ExtractorFuzzerBase` also has support for memory based buffer
`BufferSource` since the fuzzing engine feeds data using memory buffers and
usage of standard data source objects like FileSource, HTTPSource, etc. is
not feasible.

# <a name="mp4ExtractorFuzzer"></a> Fuzzer for libmp4extractor

## Plugin Design Considerations
The fuzzer plugin for MP4 extractor uses the `ExtractorFuzzerBase` class and
implements only the `createExtractor` to create the MP4 extractor class.

##### Maximize code coverage
Dict file (dictionary file) is created for MP4 to ensure that the required MP4
atoms are present in every input file that goes to the fuzzer.
This ensures that larger code gets covered as a range of MP4 atoms will be
present in the input data.


## Build

This describes steps to build mp4_extractor_fuzzer binary.

### Android

#### Steps to build
Build the fuzzer
```
  $ mm -j$(nproc) mp4_extractor_fuzzer
```

#### Steps to run
Create a directory CORPUS_DIR and copy some MP4 files to that folder
Push this directory to device.

To run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/mp4_extractor_fuzzer/mp4_extractor_fuzzer CORPUS_DIR
```

## References:
 * http://llvm.org/docs/LibFuzzer.html
 * https://github.com/google/oss-fuzz
