## Media Testing ##
---
#### Writer :
The Writer Test Suite validates the writers available in libstagefright.

Run the following steps to build the test suite:
```
mmm frameworks/av/media/libstagefright/tests/writer/
```

The 32-bit binaries will be created in the following path : ${OUT}/data/nativetest/
The 64-bit binaries will be created in the following path : ${OUT}/data/nativetest64/

To test 64-bit binary push binaries from nativetest64.

adb push ${OUT}/data/nativetest64/writerTest/writerTest /data/local/tmp/

To test 32-bit binary push binaries from nativetest.

adb push ${OUT}/data/nativetest/writerTest/writerTest /data/local/tmp/

The resource file for the tests is taken from Codec2 VTS resource folder. Push these files into device for testing.
```
adb push  $ANDROID_BUILD_TOP/frameworks/av/media/codec2/hidl/1.0/vts/functional/res /sdcard/
```

usage: writerTest -P \<path_to_res_folder\>
```
adb shell /data/local/tmp/writerTest -P /sdcard/res/
```
