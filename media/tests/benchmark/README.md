# Benchmark tests

Benchmark app analyses the time taken by MediaCodec, MediaExtractor and MediaMuxer for given set of inputs. It is used to benchmark these modules on android devices.
Benchmark results are published as a CSV report.

This page describes steps to run the NDK and SDK layer test.

Run the following steps to build the test suite:
```
mmm frameworks/av/media/tests/benchmark/
```

# Resources
The resource file for the tests is taken from [here](https://storage.googleapis.com/android_media/frameworks/av/media/tests/benchmark/MediaBenchmark.zip)

Download the MediaBenchmark.zip file, unzip and push it to /data/local/tmp/ on the device.

```
unzip MediaBenchmark.zip
adb push MediaBenchmark /data/local/tmp/MediaBenchmark/res/
```

The resource files are assumed to be at /data/local/tmp/MediaBenchmark/res/. You can use a different location, but you have to modify the rest of the instructions to replace /data/local/tmp/MediaBenchmark/res/ with wherever you chose to put the files.

# NDK CLI Tests
Note: [Benchmark Application](#BenchmarkApplication) now supports profiling both SDK and NDK APIs and that is the preferred way to benchmark codecs

To run the test suite for measuring performance of the native layer, follow the following steps:

The 64-bit binaries will be created in the following path : ${OUT}/data/nativetest64/

To test 64-bit binary push binaries from nativetest64.

adb push $OUT/data/nativetest64/* /data/local/tmp/. For example

```
adb push $OUT/data/nativetest64/extractorTest/extractorTest /data/local/tmp/
```

The 32-bit binaries will be created in the following path : ${OUT}/data/nativetest/

To test 32-bit binary push binaries from nativetest.

adb push $OUT/data/nativetest/* /data/local/tmp/. For example

```
adb push $OUT/data/nativetest/extractorTest/extractorTest /data/local/tmp/
```

To run the binary, follow the commands mentioned below under each module.

## Extractor

The test extracts elementary stream and benchmarks the extractors available in NDK.

```
adb shell /data/local/tmp/extractorTest -P /data/local/tmp/MediaBenchmark/res/
```

## Decoder

The test decodes input stream and benchmarks the decoders available in NDK.

```
adb shell /data/local/tmp/decoderTest -P /data/local/tmp/MediaBenchmark/res/
```

## Muxer

The test muxes elementary stream and benchmarks the muxers available in NDK.

```
adb shell /data/local/tmp/muxerTest -P /data/local/tmp/MediaBenchmark/res/
```

## Encoder

The test encodes input stream and benchmarks the encoders available in NDK.

```
adb shell /data/local/tmp/encoderTest -P /data/local/tmp/MediaBenchmark/res/
```

# <a name="BenchmarkApplication"></a> Benchmark Application
To run the test suite for measuring performance of the SDK and NDK APIs, follow the following steps:
Benchmark Application can be run in two ways.

## Steps to run with atest
Note that atest command will install Benchmark application and push the required test files to the device as well.

For running all the tests, run the following command
```
atest com.android.media.benchmark.tests -- --enable-module-dynamic-download=true
```

For running the tests individually, run the following atest commands:

```
atest com.android.media.benchmark.tests.ExtractorTest -- --enable-module-dynamic-download=true
atest com.android.media.benchmark.tests.DecoderTest -- --enable-module-dynamic-download=true
atest com.android.media.benchmark.tests.MuxerTest -- --enable-module-dynamic-download=true
atest com.android.media.benchmark.tests.EncoderTest -- --enable-module-dynamic-download=true
```

## Steps to run without atest

The apk will be created at the following path:

The 64-bit apk will be created in the following path :
$OUT/testcases/MediaBenchmarkTest/arm64/

For installing the apk, run the command:
```
adb install -f -r $OUT/testcases/MediaBenchmarkTest/arm64/MediaBenchmarkTest.apk
```

The 32-bit apk will be created in the following path :
$OUT/testcases/MediaBenchmarkTest/arm/

For installing the apk, run the command:
```
adb install -f -r $OUT/testcases/MediaBenchmarkTest/arm/MediaBenchmarkTest.apk
```

To get the resource files for the test follow instructions given in [Resources](#Resources)

For running all the tests, run the following command
```
adb shell am instrument -w -r -e package com.android.media.benchmark.tests com.android.media.benchmark/androidx.test.runner.AndroidJUnitRunner
```

## Extractor

The test extracts elementary stream and benchmarks the extractors available in SDK and NDK.
```
adb shell am instrument -w -r -e class 'com.android.media.benchmark.tests.ExtractorTest' com.android.media.benchmark/androidx.test.runner.AndroidJUnitRunner
```

## Decoder

The test decodes input stream and benchmarks the decoders available in SDK and NDK.
```
adb shell am instrument -w -r -e class 'com.android.media.benchmark.tests.DecoderTest' com.android.media.benchmark/androidx.test.runner.AndroidJUnitRunner
```

## Muxer

The test muxes elementary stream and benchmarks different writers available in SDK and NDK.
```
adb shell am instrument -w -r -e class 'com.android.media.benchmark.tests.MuxerTest' com.android.media.benchmark/androidx.test.runner.AndroidJUnitRunner
```

## Encoder

The test encodes input stream and benchmarks the encoders available in SDK and NDK.
```
adb shell am instrument -w -r -e class 'com.android.media.benchmark.tests.EncoderTest' com.android.media.benchmark/androidx.test.runner.AndroidJUnitRunner
```

# Codec2
To run the test suite for measuring performance of the codec2 layer, follow the following steps:

The 32-bit binaries will be created in the following path : ${OUT}/data/nativetest/

The 64-bit binaries will be created in the following path : ${OUT}/data/nativetest64/

To test 64-bit binary push binaries from nativetest64.
adb push $(OUT)/data/nativetest64/* /data/local/tmp/
```
adb push $(OUT)/data/nativetest64/C2DecoderTest/C2DecoderTest /data/local/tmp/
```

To test 32-bit binary push binaries from nativetest.
adb push $(OUT)/data/nativetest/* /data/local/tmp/
```
adb push $(OUT)/data/nativetest/C2DecoderTest/C2DecoderTest /data/local/tmp/
```

To get the resource files for the test follow instructions given in [Resources](#Resources)

## C2 Decoder

The test decodes input stream and benchmarks the codec2 decoders available in device.

```
adb shell /data/local/tmp/C2DecoderTest -P /data/local/tmp/MediaBenchmark/res/
```
## C2 Encoder

The test encodes input stream and benchmarks the codec2 encoders available in device.

```
adb shell /data/local/tmp/C2EncoderTest -P /data/local/tmp/MediaBenchmark/res/
```

# Analysis

The benchmark results are stored in a CSV file which can be used for analysis. These results are stored in following format:
<app directory>/<module_name>.<timestamp>.csv

Note: This timestamp is in nano seconds and will change based on current system time.

To find the location of the CSV file, look for the path in logs. Example log below -

```
com.android.media.benchmark D/DecoderTest: Saving Benchmark results in: /storage/emulated/0/Android/data/com.android.media.benchmark/files/Decoder.1587732395387.csv
```

This file can be pulled from the device using "adb pull" command.
```
adb pull /storage/emulated/0/Android/data/com.android.media.benchmark/files/Decoder.1587732395387.csv ./Decoder.1587732395387.csv
```

## CSV Columns

Following columns are available in CSV.

Note: All time values are in nano seconds

1. **currentTime** : The time recorded at the creation of the stats. This may be used to estimate time between consecutive test clips.

2. **fileName**: The file being used as an input for the benchmark test.

3. **operation**: The current operation on the input test vector i.e. Extract/Mux/Encode/Decode.

4. **NDK/SDK**: The target APIs i.e. AMedia vs Media calls for the operation being performed.

5. **sync/async**: This is specific to MediaCodec objects (i.e. Encoder and Decoder). It specifies the mode in which MediaCodec APIs are working. For async mode, callbacks are set. For sync mode, we have to poll the dequeueBuffer APIs to queue and dequeue input output buffers respectively.

6. **setupTime**: The time taken to set up the MediaExtractor/Muxer/Codec instance.

    * MediaCodec: includes setting async/sync mode, configuring with a format and codec.start

    * MediaExtractor: includes AMediaExtractor_new and setDataSource.

    * MediaMuxer: includes creating the object, adding track, and starting the muxer.

7. **destroyTime**: The time taken to stop and close MediaExtractor/Muxer/Codec instance.

8. **minimumTime**: The minimum time taken to extract/mux/encode/decode a frame.

9. **maximumTime**: The maximum time taken to extract/mux/encode/decode a frame.

10. **averageTime**: Average time taken to extract/mux/encode/decode per frame.

    * MediaCodec: computed as the total time taken to encode/decode all frames divided by the number of frames encoded/decoded.

    * MediaExtractor: computed as the total time taken to extract all frames divided by the number of frames extracted.

    * MediaMuxer: computed as the total time taken to mux all frames divided by the number of frames muxed.

11. **timeToProcess1SecContent**: The time required to process one second worth input data.

12. **totalBytesProcessedPerSec**: The number of bytes extracted/muxed/decoded/encoded per second.

13. **timeToFirstFrame**: The time taken to receive the first output frame.

14. **totalSizeInBytes**: The total output size of the operation (in bytes).

15. **totalTime**: The time taken to perform the complete operation (i.e. Extract/Mux/Decode/Encode) for respective test vector.


## Muxer
1. **componentName**: The format of the output Media file. Following muxers are currently supported:
     * Ogg, Webm, 3gpp, and mp4.

## Decoder
1. **componentName**: Includes all supported codecs on the device. Aliased components are skipped.
    *   Video: H263, H264, H265, VPx, Mpeg4, Mpeg2, AV1
    *   Audio: AAC, Flac, Opus, MP3, Vorbis, GSM, AMR-NB/WB

## Encoder
1. **componentName**: Includes all supported codecs on the device. Aliased components are skipped.
    *   Video: H263, H264, H265, VPx, Mpeg4
    *   Audio: AAC, Flac, Opus, AMR-NB/WB

## Common Failures
On some devices, if a codec isn't supported some tests may report a failure like "codec not found for"

For example: On mobile devices without support for mpeg2 decoder, following failure is observed:
```
Unable to create codec by mime: video/mpeg2
```
