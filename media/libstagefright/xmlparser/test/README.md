## Media Testing ##
---
#### XML Parser
The XMLParser Test Suite validates the XMLParser available in libstagefright.

Run the following steps to build the test suite:
```
m XMLParserTest
```

The 32-bit binaries will be created in the following path : ${OUT}/data/nativetest/

The 64-bit binaries will be created in the following path : ${OUT}/data/nativetest64/

To test 64-bit binary push binaries from nativetest64.
```
adb push ${OUT}/data/nativetest64/XMLParserTest/XMLParserTest /data/local/tmp/
```

To test 32-bit binary push binaries from nativetest.
```
adb push ${OUT}/data/nativetest/XMLParserTest/XMLParserTest /data/local/tmp/
```

usage: XMLParserTest
```
adb shell /data/local/tmp/XMLParserTest
```
Alternatively, the test can also be run using atest command.

```
atest XMLParserTest
```
