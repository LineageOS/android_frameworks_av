# Fuzzer for extractors

## Table of contents
+ [libextractorfuzzerbase](#ExtractorFuzzerBase)
+ [libmp4extractor](#mp4ExtractorFuzzer)
+ [libwavextractor](#wavExtractorFuzzer)
+ [libamrextractor](#amrExtractorFuzzer)
+ [libmkvextractor](#mkvExtractorFuzzer)
+ [liboggextractor](#oggExtractorFuzzer)
+ [libmpeg2extractor](#mpeg2ExtractorFuzzer)
+ [libmp3extractor](#mp3ExtractorFuzzer)
+ [libaacextractor](#aacExtractorFuzzer)

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

# <a name="amrExtractorFuzzer"></a> Fuzzer for libamrextractor

## Plugin Design Considerations
The fuzzer plugin for AMR extractor uses the `ExtractorFuzzerBase` class and
implements only the `createExtractor` to create the AMR extractor class.

##### Maximize code coverage
Dict file (dictionary file) is created for AMR to ensure that the required start
bytes are present in every input file that goes to the fuzzer.
This ensures that larger code gets covered.


## Build

This describes steps to build amr_extractor_fuzzer binary.

### Android

#### Steps to build
Build the fuzzer
```
  $ mm -j$(nproc) amr_extractor_fuzzer
```

#### Steps to run
Create a directory CORPUS_DIR and copy some AMR files to that folder
Push this directory to device.

To run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/amr_extractor_fuzzer/amr_extractor_fuzzer CORPUS_DIR
```

# <a name="mkvExtractorFuzzer"></a> Fuzzer for libmkvextractor

## Plugin Design Considerations
The fuzzer plugin for MKV extractor uses the `ExtractorFuzzerBase` class and
implements only the `createExtractor` to create the MKV extractor class.

##### Maximize code coverage
Dict file (dictionary file) is created for MKV to ensure that the required element
ID's are present in every input file that goes to the fuzzer.
This ensures that larger code gets covered.


## Build

This describes steps to build mkv_extractor_fuzzer binary.

### Android

#### Steps to build
Build the fuzzer
```
  $ mm -j$(nproc) mkv_extractor_fuzzer
```

#### Steps to run
Create a directory CORPUS_DIR and copy some mkv files to that folder.
Push this directory to device.

To run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/mkv_extractor_fuzzer/mkv_extractor_fuzzer CORPUS_DIR
```

# <a name="oggExtractorFuzzer"></a> Fuzzer for liboggextractor

## Plugin Design Considerations
The fuzzer plugin for OGG extractor uses the `ExtractorFuzzerBase` class and
implements only the `createExtractor` to create the OGG extractor object.

##### Maximize code coverage
Dict file (dictionary file) is created for OGG to ensure that the required start
bytes are present in every input file that goes to the fuzzer.
This ensures that larger code gets covered.


## Build

This describes steps to build ogg_extractor_fuzzer binary.

### Android

#### Steps to build
Build the fuzzer
```
  $ mm -j$(nproc) ogg_extractor_fuzzer
```

#### Steps to run
Create a directory CORPUS_DIR and copy some ogg files to that folder.
Push this directory to device.

To run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/ogg_extractor_fuzzer/ogg_extractor_fuzzer CORPUS_DIR
```

# <a name="mpeg2ExtractorFuzzer"></a> Fuzzer for libmpeg2extractor

## Plugin Design Considerations
The fuzzer plugins for MPEG2-PS and MPEG2-TS extractor use the `ExtractorFuzzerBase` class and
implement only the `createExtractor` to create the MPEG2-PS or MPEG2-TS extractor
object respectively.

##### Maximize code coverage
Dict files (dictionary files) are created for MPEG2-PS and MPEG2-TS to ensure that the
required start bytes are present in every input file that goes to the fuzzer.
This ensures that larger code gets covered.

##### Other considerations
Two fuzzer binaries - mpeg2ps_extractor_fuzzer and mpeg2ts_extractor_fuzzer are
generated based on the presence of a flag - `MPEG2PS`


## Build

This describes steps to build mpeg2ps_extractor_fuzzer and mpeg2ts_extractor_fuzzer binary.

### Android

#### Steps to build
Build the fuzzer
```
  $ mm -j$(nproc) mpeg2ps_extractor_fuzzer
  $ mm -j$(nproc) mpeg2ts_extractor_fuzzer
```

#### Steps to run
Create a directory CORPUS_DIR and copy some mpeg2 files to that folder
Push this directory to device.

To run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/mpeg2ps_extractor_fuzzer/mpeg2ps_extractor_fuzzer CORPUS_DIR
  $ adb shell /data/fuzz/arm64/mpeg2ts_extractor_fuzzer/mpeg2ts_extractor_fuzzer CORPUS_DIR
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

## References:
 * http://llvm.org/docs/LibFuzzer.html
 * https://github.com/google/oss-fuzz
