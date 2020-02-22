## Media Testing ##
---
#### Mp3Decoder :
The Mp3Decoder Test Suite validates the mp3decoder available in libstagefright.

Run the following steps to build the test suite:
```
m Mp3DecoderTest
```

The 32-bit binaries will be created in the following path : ${OUT}/data/nativetest/

The 64-bit binaries will be created in the following path : ${OUT}/data/nativetest64/

To test 64-bit binary push binaries from nativetest64.
```
adb push ${OUT}/data/nativetest64/Mp3DecoderTest/Mp3DecoderTest /data/local/tmp/
```

To test 32-bit binary push binaries from nativetest.
```
adb push ${OUT}/data/nativetest/Mp3DecoderTest/Mp3DecoderTest /data/local/tmp/
```

The resource file for the tests is taken from [here](https://storage.googleapis.com/android_media/frameworks/av/media/libstagefright/mp3dec/test/Mp3DecoderTest.zip). Download, unzip and push these files into device for testing.

```
adb push Mp3DecoderTestRes/. /data/local/tmp/
```

usage: Mp3DecoderTest -P \<path_to_folder\>
```
adb shell /data/local/tmp/Mp3DecoderTest -P /data/local/tmp/Mp3DecoderTestRes/
```
Alternatively, the test can also be run using atest command.

```
atest Mp3DecoderTest -- --enable-module-dynamic-download=true
```
