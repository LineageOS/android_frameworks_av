## Media Testing ##
---
#### AMR-WB Encoder :
The Amr-Wb Encoder Test Suite validates the amrwb encoder available in libstagefright.

Run the following steps to build the test suite:
```
m AmrwbEncoderTest
```

The 32-bit binaries will be created in the following path : ${OUT}/data/nativetest/

The 64-bit binaries will be created in the following path : ${OUT}/data/nativetest64/

To test 64-bit binary push binaries from nativetest64.
```
adb push ${OUT}/data/nativetest64/AmrwbEncoderTest/AmrwbEncoderTest /data/local/tmp/
```

To test 32-bit binary push binaries from nativetest.
```
adb push ${OUT}/data/nativetest/AmrwbEncoderTest/AmrwbEncoderTest /data/local/tmp/
```

The resource file for the tests is taken from [here](https://storage.googleapis.com/android_media/frameworks/av/media/libstagefright/codecs/amrwbenc/test/AmrwbEncoderTest.zip). Download, unzip and push these files into device for testing.

```
adb push AmrwbEncoderTestRes/. /data/local/tmp/
```

usage: AmrwbEncoderTest -P \<path_to_folder\>
```
adb shell /data/local/tmp/AmrwbEncoderTest -P /data/local/tmp/AmrwbEncoderTestRes/
```
Alternatively, the test can also be run using atest command.

```
atest AmrwbEncoderTest -- --enable-module-dynamic-download=true
```
