## Media Testing ##
---
#### AMR-WB Decoder :
The Amr-Wb Decoder Test Suite validates the amrwb decoder available in libstagefright.

Run the following steps to build the test suite:
```
m AmrwbDecoderTest
```

The 32-bit binaries will be created in the following path : ${OUT}/data/nativetest/

The 64-bit binaries will be created in the following path : ${OUT}/data/nativetest64/

To test 64-bit binary push binaries from nativetest64.
```
adb push ${OUT}/data/nativetest64/AmrwbDecoderTest/AmrwbDecoderTest /data/local/tmp/
```

To test 32-bit binary push binaries from nativetest.
```
adb push ${OUT}/data/nativetest/AmrwbDecoderTest/AmrwbDecoderTest /data/local/tmp/
```

The resource file for the tests is taken from [here](https://drive.google.com/drive/folders/13cM4tAaVFrmr-zGFqaAzFBbKs75pnm9b). Push these files into device for testing.
Download amr-wb folder and push all the files in this folder to /data/local/tmp/ on the device.
```
adb push amr-wb/. /data/local/tmp/
```

usage: AmrwbDecoderTest -P \<path_to_folder\>
```
adb shell /data/local/tmp/AmrwbDecoderTest -P /data/local/tmp/
```
