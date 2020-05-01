# Fuzzer for extractors

## Table of contents
+ [libextractorfuzzerbase](#ExtractorFuzzerBase)
+ [libmp4extractor](#mp4ExtractorFuzzer)
+ [libwavextractor](#wavExtractorFuzzer)
+ [libmp3extractor](#mp3ExtractorFuzzer)
+ [libaacextractor](#aacExtractorFuzzer)
+ [libflacextractor](#flacExtractor)

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

# <a name="wavExtractorFuzzer"></a> Fuzzer for libwavextractor

## Plugin Design Considerations
The fuzzer plugin for WAV extractor uses the `ExtractorFuzzerBase` class and
implements only the `createExtractor` to create the WAV extractor class.


## Build

This describes steps to build wav_extractor_fuzzer binary.

### Android

#### Steps to build
Build the fuzzer
```
  $ mm -j$(nproc) wav_extractor_fuzzer
```

#### Steps to run
Create a directory CORPUS_DIR and copy some wav files to that folder
Push this directory to device.

To run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/wav_extractor_fuzzer/wav_extractor_fuzzer CORPUS_DIR
```

# <a name="mp3ExtractorFuzzer"></a> Fuzzer for libmp3extractor

## Plugin Design Considerations
The fuzzer plugin for MP3 extractor uses the `ExtractorFuzzerBase` class and
implements only the `createExtractor` to create the MP3 extractor class.


## Build

This describes steps to build mp3_extractor_fuzzer binary.

### Android

#### Steps to build
Build the fuzzer
```
  $ mm -j$(nproc) mp3_extractor_fuzzer
```

#### Steps to run
Create a directory CORPUS_DIR and copy some mp3 files to that folder
Push this directory to device.

To run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/mp3_extractor_fuzzer/mp3_extractor_fuzzer CORPUS_DIR
```

# <a name="aacExtractorFuzzer"></a> Fuzzer for libaacextractor

## Plugin Design Considerations
The fuzzer plugin for AAC extractor uses the `ExtractorFuzzerBase` class and
implements only the `createExtractor` to create the AAC extractor class.


## Build

This describes steps to build aac_extractor_fuzzer binary.

### Android

#### Steps to build
Build the fuzzer
```
  $ mm -j$(nproc) aac_extractor_fuzzer
```

#### Steps to run
Create a directory CORPUS_DIR and copy some aac files to that folder
Push this directory to device.

To run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/aac_extractor_fuzzer/aac_extractor_fuzzer CORPUS_DIR
```

# <a name="flacExtractor"></a> Fuzzer for libflacextractor

## Plugin Design Considerations
The fuzzer plugin for FLAC extractor uses the `ExtractorFuzzerBase` class and
implements only the `createExtractor` to create the FLAC extractor object.

##### Maximize code coverage
Dict file (dictionary file) is created for FLAC to ensure that the required start
bytes are present in every input file that goes to the fuzzer.
This ensures that larger code gets covered.


## Build

This describes steps to build flac_extractor_fuzzer binary.

### Android

#### Steps to build
Build the fuzzer
```
  $ mm -j$(nproc) flac_extractor_fuzzer
```

#### Steps to run
Create a directory CORPUS_DIR and copy some flac files to that folder
Push this directory to device.

To run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/flac_extractor_fuzzer/flac_extractor_fuzzer CORPUS_DIR
```

## References:
 * http://llvm.org/docs/LibFuzzer.html
 * https://github.com/google/oss-fuzz
