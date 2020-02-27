## Media Testing ##
---
#### AMR-NB Encoder :
The Amr-Nb Encoder Test Suite validates the amrnb encoder available in libstagefright.

Run the following steps to build the test suite:
```
m AmrnbEncoderTest
```

The 32-bit binaries will be created in the following path : ${OUT}/data/nativetest/

The 64-bit binaries will be created in the following path : ${OUT}/data/nativetest64/

To test 64-bit binary push binaries from nativetest64.
```
adb push ${OUT}/data/nativetest64/AmrnbEncoderTest/AmrnbEncoderTest /data/local/tmp/
```

To test 32-bit binary push binaries from nativetest.
```
adb push ${OUT}/data/nativetest/AmrnbEncoderTest/AmrnbEncoderTest /data/local/tmp/
```

The resource file for the tests is taken from [here](https://storage.googleapis.com/android_media/frameworks/av/media/libstagefright/codecs/amrnb/enc/test/AmrnbEncoderTest.zip). Download, unzip and push these files into device for testing.

```
adb push AmrnbEncoderTestRes/. /data/local/tmp/
```

usage: AmrnbEncoderTest -P \<path_to_folder\>
```
adb shell /data/local/tmp/AmrnbEncoderTest -P /data/local/tmp/AmrnbEncoderTestRes/
```
Alternatively, the test can also be run using atest command.

```
atest AmrnbEncoderTest -- --enable-module-dynamic-download=true
```
