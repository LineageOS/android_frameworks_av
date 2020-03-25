## Media Testing ##
---
#### Mpeg2TS Unit Test :
The Mpeg2TS Unit Test Suite validates the functionality of the libraries present in Mpeg2TS.

Run the following steps to build the test suite:
```
mmm frameworks/av/media/libstagefright/mpeg2ts/test/
```

The 32-bit binaries will be created in the following path : ${OUT}/data/nativetest/

The 64-bit binaries will be created in the following path : ${OUT}/data/nativetest64/

To test 64-bit binary push binaries from nativetest64.

adb push ${OUT}/data/nativetest64/Mpeg2tsUnitTest/Mpeg2tsUnitTest /data/local/tmp/

To test 32-bit binary push binaries from nativetest.

adb push ${OUT}/data/nativetest/Mpeg2tsUnitTest/Mpeg2tsUnitTest /data/local/tmp/

The resource file for the tests is taken from [here](https://storage.googleapis.com/android_media/frameworks/av/media/libstagefright/mpeg2ts/test/Mpeg2tsUnitTest.zip ).
Download, unzip and push these files into device for testing.

```
adb push Mpeg2tsUnitTestRes/. /data/local/tmp/
```

usage: Mpeg2tsUnitTest -P \<path_to_folder\>
```
adb shell /data/local/tmp/Mpeg2tsUnitTest -P /data/local/tmp/Mpeg2tsUnitTestRes/
```
Alternatively, the test can also be run using atest command.

```
atest Mpeg2tsUnitTest -- --enable-module-dynamic-download=true
```
