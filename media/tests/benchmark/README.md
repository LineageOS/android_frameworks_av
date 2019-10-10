# Benchmark tests

Benchmark app analyses the time taken by MediaCodec, MediaExtractor and MediaMuxer for given set of inputs. It is used to benchmark these modules on android devices.
Benchmark results are emitted to logcat.

This page describes steps to run the NDK and SDK layer test.

Run the following steps to build the test suite:
```
mmm frameworks/av/media/tests/benchmark/
```
To run the test suite for measuring performance of the native layer, follow the following steps:
# NDK

The binaries will be created in the following path : ${OUT}/data/nativetest64/

adb push $(OUT)/data/nativetest64/* /data/local/tmp/

Eg. adb push $(OUT)/data/nativetest64/extractorTest/extractorTest /data/local/tmp/

To run the binary, follow the commands mentioned below under each module.

The resource file for the tests is taken from [here](https://drive.google.com/open?id=1ghMr17BBJ7n0pqbm7oREiTN_MNemJUqy)

Download the MediaBenchmark.zip file, unzip and push it to /data/local/tmp/ on the device.

```
unzip MediaBenchmark.zip
adb push MediaBenchmark /data/local/tmp
```

## Extractor

The test extracts elementary stream and benchmarks the extractors available in NDK.

The resource files are assumed to be at /data/local/tmp/MediaBenchmark/res/. You can use a different location, but you have to modify the rest of the instructions to replace /data/local/tmp/MediaBenchmark/res/ with wherever you chose to put the files.

The path to these files on the device is required to be given for the test.

```
adb shell /data/local/tmp/extractorTest -P /data/local/tmp/MediaBenchmark/res/
```

## Decoder

The test decodes input stream and benchmarks the decoders available in NDK.

Setup steps are same as extractor.

```
adb shell /data/local/tmp/decoderTest -P /data/local/tmp/MediaBenchmark/res/
```

## Muxer

The test muxes elementary stream and benchmarks the muxers available in NDK.

Setup steps are same as extractor.

```
adb shell /data/local/tmp/muxerTest -P /data/local/tmp/MediaBenchmark/res/
```

## Encoder

The test encodes input stream and benchmarks the encoders available in NDK.

Setup steps are same as extractor.

```
adb shell /data/local/tmp/encoderTest -P /data/local/tmp/MediaBenchmark/res/
```

# SDK

To run the test suite for measuring performance of the SDK APIs, follow the following steps:

The apk will be created at the following path:
${OUT}/testcases/MediaBenchmarkApp/arm64/

To get the resorce files for the test follow instructions given in [NDK](#NDK)

For installing the apk, run the command:
```
adb install -f -r ${OUT}/testcases/MediaBenchmarkApp/arm64/MediaBenchmarkApp.apk
```

For running all the tests, run the command:
```
adb shell am instrument -w -r -e package com.android.media.benchmark.tests com.android.media.benchmark/androidx.test.runner.AndroidJUnitRunner
```

## Extractor

The test extracts elementary stream and benchmarks the extractors available in SDK.
```
adb shell am instrument -w -r -e class 'com.android.media.benchmark.tests.ExtractorTest' com.android.media.benchmark/androidx.test.runner.AndroidJUnitRunner
```
