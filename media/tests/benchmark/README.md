# Benchmark tests

Run the following steps to build the test suite:
```
mmm frameworks/av/media/tests/benchmark/
```

The binaries will be created in the following path : ${OUT}/data/nativetest64/

adb push $(OUT)/data/nativetest64/* /data/local/tmp/

Eg. adb push $(OUT)/data/nativetest64/extractorTest/extractorTest /data/local/tmp/

To run the binary, follow the commands mentioned below under each module.

The resource files for the tests are taken from [here](https://drive.google.com/open?id=1ghMr17BBJ7n0pqbm7oREiTN_MNemJUqy)

## Extractor

The test extracts elementary stream and benchmarks the extractors available in NDK.

Push the resource files to /sdcard/res on the device.

You can use a different location, but you have to modify the rest of the instructions to replace /sdcard/res with wherever you chose to put the files.

The path to these files on the device is required to be given for the test.

```
adb shell /data/local/tmp/extractorTest -P /sdcard/res/
```

## Decoder

The test decodes input stream and benchmarks the decoders available in NDK.

Setup steps are same as extractor.

```
adb shell /data/local/tmp/decoderTest -P /sdcard/res/
```

## Muxer

The test muxes elementary stream and benchmarks the muxers available in NDK.

Setup steps are same as extractor.

```
adb shell /data/local/tmp/muxerTest -P /sdcard/res/
```

## Encoder

The test encodes input stream and benchmarks the encoders available in NDK.

Setup steps are same as extractor.

```
adb shell /data/local/tmp/encoderTest -P /sdcard/res/
```
