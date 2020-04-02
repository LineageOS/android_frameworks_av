## Media Testing ##
---
#### TimedText Unit Test :
The TimedText Unit Test Suite validates the TextDescription class available in libstagefright.

Run the following steps to build the test suite:
```
m TimedTextUnitTest
```

The 32-bit binaries will be created in the following path : ${OUT}/data/nativetest/

The 64-bit binaries will be created in the following path : ${OUT}/data/nativetest64/

To test 64-bit binary push binaries from nativetest64.
```
adb push ${OUT}/data/nativetest64/TimedTextUnitTest/TimedTextUnitTest /data/local/tmp/
```

To test 32-bit binary push binaries from nativetest.
```
adb push ${OUT}/data/nativetest/TimedTextUnitTest/TimedTextUnitTest /data/local/tmp/
```

The resource file for the tests is taken from [here](https://storage.googleapis.com/android_media/frameworks/av/media/libstagefright/timedtext/test/TimedTextUnitTest.zip).
Download, unzip and push these files into device for testing.

```
adb push TimedTextUnitTestRes/. /data/local/tmp/
```

usage: TimedTextUnitTest -P \<path_to_folder\>
```
adb shell /data/local/tmp/TimedTextUnitTest -P /data/local/tmp/TimedTextUnitTestRes/
```
Alternatively, the test can also be run using atest command.

```
atest TimedTextUnitTest -- --enable-module-dynamic-download=true
```
