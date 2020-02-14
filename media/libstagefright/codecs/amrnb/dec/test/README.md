## Media Testing ##
---
#### AMR-NB Decoder :
The Amr-Nb Decoder Test Suite validates the amrnb decoder available in libstagefright.

Run the following steps to build the test suite:
```
m AmrnbDecoderTest
```

The 32-bit binaries will be created in the following path : ${OUT}/data/nativetest/

The 64-bit binaries will be created in the following path : ${OUT}/data/nativetest64/

To test 64-bit binary push binaries from nativetest64.
```
adb push ${OUT}/data/nativetest64/AmrnbDecoderTest/AmrnbDecoderTest /data/local/tmp/
```

To test 32-bit binary push binaries from nativetest.
```
adb push ${OUT}/data/nativetest/AmrnbDecoderTest/AmrnbDecoderTest /data/local/tmp/
```

The resource file for the tests is taken from [here](https://storage.googleapis.com/android_media/frameworks/av/media/libstagefright/codecs/amrnb/dec/test/AmrnbDecoderTest.zip). Download, unzip and push these files into device for testing.

```
adb push AmrnbDecoderTestRes/. /data/local/tmp/
```

usage: AmrnbDecoderTest -P \<path_to_folder\>
```
adb shell /data/local/tmp/AmrnbDecoderTest -P /data/local/tmp/AmrnbDecoderTestRes/
```
Alternatively, the test can also be run using atest command.

```
atest AmrnbDecoderTest -- --enable-module-dynamic-download=true
```
