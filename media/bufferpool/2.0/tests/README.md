## Media Testing ##
---
#### Bufferpool :
The Bufferpool Test Suite validates bufferpool library in android.

Run the following steps to build the test suite:
```
m BufferpoolUnitTest
```

The 32-bit binaries will be created in the following path : ${OUT}/data/nativetest/

The 64-bit binaries will be created in the following path : ${OUT}/data/nativetest64/

To test 64-bit binary push binaries from nativetest64.
```
adb push ${OUT}/data/nativetest64/BufferpoolUnitTest/BufferpoolUnitTest /data/local/tmp/
```

To test 32-bit binary push binaries from nativetest.
```
adb push ${OUT}/data/nativetest/BufferpoolUnitTest/BufferpoolUnitTest /data/local/tmp/
```

usage: BufferpoolUnitTest
```
adb shell /data/local/tmp/BufferpoolUnitTest
```
Alternatively, the test can also be run using atest command.

```
atest BufferpoolUnitTest
```
