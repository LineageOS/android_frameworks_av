## Media Testing ##
---
#### AMR-WB Encoder :
The Amr-Wb Encoder Test Suite validates the amrwb encoder available in libstagefright.

Run the following steps to build the test suite:
```
m AmrwbEncoderTest
```

The 32-bit binaries will be created in the following path : ${OUT}/data/nativetest/

The 64-bit binaries will be created in the following path : ${OUT}/data/nativetest64/

To test 64-bit binary push binaries from nativetest64.
```
adb push ${OUT}/data/nativetest64/AmrwbEncoderTest/AmrwbEncoderTest /data/local/tmp/
```

To test 32-bit binary push binaries from nativetest.
```
adb push ${OUT}/data/nativetest/AmrwbEncoderTest/AmrwbEncoderTest /data/local/tmp/
```

The resource file for the tests is taken from [here](https://drive.google.com/drive/folders/13cM4tAaVFrmr-zGFqaAzFBbKs75pnm9b). Push these files into device for testing.
Download amr-wb_encoder folder and push all the files in this folder to /data/local/tmp/ on the device.
```
adb push amr-wb_encoder/. /data/local/tmp/
```

usage: AmrwbEncoderTest -P \<path_to_folder\>
```
adb shell /data/local/tmp/AmrwbEncoderTest -P /data/local/tmp/
```
