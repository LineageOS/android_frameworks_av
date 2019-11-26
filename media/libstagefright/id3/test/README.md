## Media Testing ##
---
#### ID3 Test :
The ID3 Test Suite validates the ID3 parser available in libstagefright.

Run the following command in the id3 folder to build the test suite:
```
m ID3Test
```

The 32-bit binaries will be created in the following path : ${OUT}/data/nativetest/

The 64-bit binaries will be created in the following path : ${OUT}/data/nativetest64/

To test 64-bit binary push binaries from nativetest64.
```
adb push ${OUT}/data/nativetest64/ID3Test/ID3Test /data/local/tmp/
```

To test 32-bit binary push binaries from nativetest.
```
adb push ${OUT}/data/nativetest/ID3Test/ID3Test /data/local/tmp/
```

The resource file for the tests is taken from [here](https://drive.google.com/drive/folders/1pt5HFVSysbqfyqY1sVJ9MTupZKCdqjYZ). Push these files into device for testing.
Download ID3 folder and push all the files in this folder to /data/local/tmp/ID3 on the device.
```
adb push ID3/. /data/local/tmp/ID3
```

usage: ID3Test -P \<path_to_folder\>
```
adb shell /data/local/tmp/ID3Test -P /data/local/tmp/ID3/
```
