## Media Testing ##
---
#### AVCUtils Test
The AVC Utility Unit Test Suite validates the avc_utils librariy available in libstagefright/foundation.

Run the following steps to build the test suite:
```
m AVCUtilsUnitTest
```

The 32-bit binaries will be created in the following path : ${OUT}/data/nativetest/

The 64-bit binaries will be created in the following path : ${OUT}/data/nativetest64/

To test 64-bit binary push binaries from nativetest64.
```
adb push ${OUT}/data/nativetest64/AVCUtilsUnitTest/AVCUtilsUnitTest /data/local/tmp/
```

To test 32-bit binary push binaries from nativetest.
```
adb push ${OUT}/data/nativetest/AVCUtilsUnitTest/AVCUtilsUnitTest /data/local/tmp/
```

The resource file for the tests is taken from [here](https://dl.google.com/android-unittest/media/frameworks/av/media/module/foundation/tests/AVCUtils/AVCUtilsUnitTest-1.0.zip). Download, unzip and push these files into device for testing.

```
adb push AVCUtilsUnitTest-1.0 /data/local/tmp/
```

usage: AVCUtilsUnitTest -P \<path_to_folder\>
```
adb shell /data/local/tmp/AVCUtilsUnitTest -P /data/local/tmp/AVCUtilsUnitTest-1.0/
```
Alternatively, the test can also be run using atest command.

```
atest AVCUtilsUnitTest -- --enable-module-dynamic-download=true
```
