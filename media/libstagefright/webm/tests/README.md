## Media Testing ##
---
#### Webm Writer Utility Tests :
The Webm Writer Utility Test Suite validates the APIs being used by the WebmWriter.

Run the following steps to build the test suite:
```
mmm frameworks/av/media/libstagefright/webm/tests/
```

The 32-bit binaries will be created in the following path : ${OUT}/data/nativetest/

The 64-bit binaries will be created in the following path : ${OUT}/data/nativetest64/

#### WebmFrameThread
To test 64-bit binary push binaries from nativetest64.

adb push ${OUT}/data/nativetest64/WebmFrameThreadUnitTest/WebmFrameThreadUnitTest /data/local/tmp/

To test 32-bit binary push binaries from nativetest.

adb push ${OUT}/data/nativetest/WebmFrameThreadUnitTest/WebmFrameThreadUnitTest /data/local/tmp/

```
adb shell /data/local/tmp/WebmFrameThreadUnitTest
```
