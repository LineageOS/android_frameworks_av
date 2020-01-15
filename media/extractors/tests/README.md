## Media Testing ##
---
#### Extractor :
The Extractor Test Suite validates the extractors available in the device.

Run the following steps to build the test suite:
```
m ExtractorUnitTest
```

The 32-bit binaries will be created in the following path : ${OUT}/data/nativetest/

The 64-bit binaries will be created in the following path : ${OUT}/data/nativetest64/

To test 64-bit binary push binaries from nativetest64.
```
adb push ${OUT}/data/nativetest64/ExtractorUnitTest/ExtractorUnitTest /data/local/tmp/
```

To test 32-bit binary push binaries from nativetest.
```
adb push ${OUT}/data/nativetest/ExtractorUnitTest/ExtractorUnitTest /data/local/tmp/
```

The resource file for the tests is taken from [here](https://drive.google.com/drive/folders/1Z9nCIRB6pGLvb5mPkF8BURa5Nc6cY9pY). Push these files into device for testing.
Download extractor folder and push all the files in this folder to /data/local/tmp/ on the device.
```
adb push extractor /data/local/tmp/
```

usage: ExtractorUnitTest -P \<path_to_folder\>
```
adb shell /data/local/tmp/ExtractorUnitTest -P /data/local/tmp/extractor/
```
