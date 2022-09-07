## Media Testing ##
---
#### AMR-WB Decoder :
The Amr-Wb Decoder Test Suite validates the amrwb decoder available in libstagefright.

Run the following steps to build the test suite:
```
m AmrwbDecoderTest
```

The 32-bit binaries will be created in the following path : ${OUT}/data/nativetest/

The 64-bit binaries will be created in the following path : ${OUT}/data/nativetest64/

To test 64-bit binary push binaries from nativetest64.
```
adb push ${OUT}/data/nativetest64/AmrwbDecoderTest/AmrwbDecoderTest /data/local/tmp/
```

To test 32-bit binary push binaries from nativetest.
```
adb push ${OUT}/data/nativetest/AmrwbDecoderTest/AmrwbDecoderTest /data/local/tmp/
```

The resource file for the tests is taken from [here](https://storage.googleapis.com/android_media/frameworks/av/media/libstagefright/codecs/amrwb/test/AmrwbDecoderTest.zip). Download, unzip and push these files into device for testing.

```
adb push AmrwbDecoderTestRes/. /data/local/tmp/
```

usage: AmrwbDecoderTest -P \<path_to_folder\>
```
adb shell /data/local/tmp/AmrwbDecoderTest -P /data/local/tmp/AmrwbDecoderTestRes/
```
Alternatively, the test can also be run using atest command.

```
atest AmrwbDecoderTest -- --enable-module-dynamic-download=true
```
