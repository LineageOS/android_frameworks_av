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

The resource file for the tests is taken from [here](https://storage.googleapis.com/android_media/frameworks/av/media/libstagefright/foundation/tests/AVCUtils/AVCUtilsUnitTest.zip). Download, unzip and push these files into device for testing.

```
adb push AVCUtilsUnitTest /data/local/tmp/
```

usage: AVCUtilsUnitTest -P \<path_to_folder\>
```
adb shell /data/local/tmp/AVCUtilsUnitTest -P /data/local/tmp/AVCUtilsUnitTest/
```
Alternatively, the test can also be run using atest command.

```
atest AVCUtilsUnitTest -- --enable-module-dynamic-download=true
```
