## Media Testing ##
---
#### Opus Header
The OpusHeader Test Suite validates the OPUS header available in libstagefright.

Run the following steps to build the test suite:
```
m OpusHeaderTest
```

The 32-bit binaries will be created in the following path : ${OUT}/data/nativetest/

The 64-bit binaries will be created in the following path : ${OUT}/data/nativetest64/

To test 64-bit binary push binaries from nativetest64.
```
adb push ${OUT}/data/nativetest64/OpusHeaderTest/OpusHeaderTest /data/local/tmp/
```

To test 32-bit binary push binaries from nativetest.
```
adb push ${OUT}/data/nativetest/OpusHeaderTest/OpusHeaderTest /data/local/tmp/
```

The resource file for the tests is taken from [here](https://storage.googleapis.com/android_media/frameworks/av/media/libstagefright/foundation/tests/OpusHeader/OpusHeader.zip). Download, unzip and push these files into device for testing.

```
adb push OpusHeader /data/local/tmp/
```

usage: OpusHeaderTest -P \<path_to_folder\>
```
adb shell /data/local/tmp/OpusHeaderTest -P /data/local/tmp/OpusHeader/
```
Alternatively, the test can also be run using atest command.

```
atest OpusHeaderTest -- --enable-module-dynamic-download=true
```
