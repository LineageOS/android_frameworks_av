## Media Testing ##
---
#### Mp3Decoder :
The Mp3Decoder Test Suite validates the mp3decoder available in libstagefright.

Run the following steps to build the test suite:
```
m Mp3DecoderTest
```

The 32-bit binaries will be created in the following path : ${OUT}/data/nativetest/

The 64-bit binaries will be created in the following path : ${OUT}/data/nativetest64/

To test 64-bit binary push binaries from nativetest64.
```
adb push ${OUT}/data/nativetest64/Mp3DecoderTest/Mp3DecoderTest /data/local/tmp/
```

To test 32-bit binary push binaries from nativetest.
```
adb push ${OUT}/data/nativetest/Mp3DecoderTest/Mp3DecoderTest /data/local/tmp/
```

The resource file for the tests is taken from [here](https://drive.google.com/drive/folders/13cM4tAaVFrmr-zGFqaAzFBbKs75pnm9b). Push these files into device for testing.
Download mp3 folder and push all the files in this folder to /data/local/tmp/ on the device.
```
adb push mp3/. /data/local/tmp/
```

usage: Mp3DecoderTest -P \<path_to_folder\>
```
adb shell /data/local/tmp/Mp3DecoderTest -P /data/local/tmp/
```
