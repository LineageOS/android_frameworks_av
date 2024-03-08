## Media Testing ##
---
#### HEVC Utils Test
The HEVC Utility Unit Test Suite validates the HevcUtils library available in libstagefright.

Run the following steps to build the test suite:
```
m HEVCUtilsUnitTest
```

The 32-bit binaries will be created in the following path : ${OUT}/data/nativetest/

The 64-bit binaries will be created in the following path : ${OUT}/data/nativetest64/

To test 64-bit binary push binaries from nativetest64.
```
adb push ${OUT}/data/nativetest64/HEVCUtilsUnitTest/HEVCUtilsUnitTest /data/local/tmp/
```

To test 32-bit binary push binaries from nativetest.
```
adb push ${OUT}/data/nativetest/HEVCUtilsUnitTest/HEVCUtilsUnitTest /data/local/tmp/
```

The resource file for the tests is taken from [here](https://dl.google.com/android-unittest/media/frameworks/av/media/libstagefright/tests/HEVC/HEVCUtilsUnitTest-1.0.zip). Download, unzip and push these files into device for testing.

```
adb push HEVCUtilsUnitTest-1.0 /data/local/tmp/
```

usage: HEVCUtilsUnitTest -P \<path_to_folder\>
```
adb shell /data/local/tmp/HEVCUtilsUnitTest -P /data/local/tmp/HEVCUtilsUnitTest-1.0/
```
Alternatively, the test can also be run using atest command.

```
atest HEVCUtilsUnitTest -- --enable-module-dynamic-download=true
```
