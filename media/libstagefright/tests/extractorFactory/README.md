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

adb push ${OUT}/data/nativetest64/ExtractorFactoryTest/ExtractorFactoryTest /data/local/tmp/

To test 32-bit binary push binaries from nativetest.

adb push ${OUT}/data/nativetest/ExtractorFactoryTest/ExtractorFactoryTest /data/local/tmp/

The resource file for the tests is taken from [here](https://storage.googleapis.com/android_media/frameworks/av/media/extractors/tests/extractor.zip).
Download, unzip and push these files into device for testing.

```
adb push extractor /data/local/tmp/
```

usage: ExtractorFactoryTest -P \<path_to_res_folder\>
```
adb shell /data/local/tmp/ExtractorFactoryTest -P /data/local/tmp/extractor/
```
Alternatively, the test can also be run using atest command.

```
atest ExtractorFactoryTest -- --enable-module-dynamic-download=true
```
