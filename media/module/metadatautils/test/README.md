## Media Testing ##
---
#### MetaDataUtils Test
The MetaDataUtils Unit Test Suite validates the libstagefright_metadatautils library available in libstagefright.

Run the following steps to build the test suite:
```
m MetaDataUtilsTest
```

The 32-bit binaries will be created in the following path : ${OUT}/data/nativetest/

The 64-bit binaries will be created in the following path : ${OUT}/data/nativetest64/

To test 64-bit binary push binaries from nativetest64.
```
adb push ${OUT}/data/nativetest64/MetaDataUtilsTest/MetaDataUtilsTest /data/local/tmp/
```

To test 32-bit binary push binaries from nativetest.
```
adb push ${OUT}/data/nativetest/MetaDataUtilsTest/MetaDataUtilsTest /data/local/tmp/
```

The resource file for the tests is taken from [here](https://storage.googleapis.com/android_media/frameworks/av/media/libstagefright/tests/metadatautils/MetaDataUtilsTestRes-1.0.zip). Download, unzip and push these files into device for testing.

```
adb push MetaDataUtilsTestRes-1.0 /data/local/tmp/
```

usage: MetaDataUtilsTest -P \<path_to_folder\>
```
adb shell /data/local/tmp/MetaDataUtilsTest -P /data/local/tmp/MetaDataUtilsTestRes-1.0/
```
Alternatively, the test can also be run using atest command.

```
atest MetaDataUtilsTest -- --enable-module-dynamic-download=true
```
