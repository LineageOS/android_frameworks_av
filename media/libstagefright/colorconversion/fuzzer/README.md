# Fuzzers for libstagefright_color_conversion

## Table of contents
+ [color_conversion_fuzzer](#ColorConversion)


# <a name="ColorConversion"></a> Fuzzer for  Colorconversion

ColorConversion supports the following parameters:
1. SrcColorFormatType (parameter name: "kSrcFormatType")
2. DstColorFormatType (parameter name: "kDstFormatType")

| Parameter| Valid Values| Configured Value|
|------------- |-------------| ----- |
|`kSrcFormatType`| 0. `OMX_COLOR_FormatYUV420Planar`<br/>1. `OMX_COLOR_FormatYUV420Planar16`<br/>2. `OMX_COLOR_FormatYUV420SemiPlanar` <br/>3. `OMX_TI_COLOR_FormatYUV420PackedSemiPlanar` <br/>4.`OMX_COLOR_FormatCbYCrY`<br/>5.`OMX_QCOM_COLOR_FormatYVU420SemiPlanar`<br/>6.`COLOR_FormatYUVP010`|Value obtained from FuzzedDataProvider|
|`kDstFormatType`| 0. `OMX_COLOR_Format16bitRGB565`<br/>1. `OMX_COLOR_Format32BitRGBA8888`<br/>2. `OMX_COLOR_Format32bitBGRA8888` <br/>3. `OMX_COLOR_Format16bitRGB565` <br/>4. `OMX_COLOR_Format32bitBGRA8888`<br/>5.`OMX_COLOR_FormatYUV444Y410`<br/>6. `COLOR_Format32bitABGR2101010`|Value obtained from FuzzedDataProvider|


#### Steps to run
1. Build the fuzzer
```
  $ mm -j$(nproc) color_conversion_fuzzer
```
2. Run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/color_conversion_fuzzer/color_conversion_fuzzer
```
