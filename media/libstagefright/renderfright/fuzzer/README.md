# Fuzzer for libstagefright_renderfright

RenderFright supports the following parameters:
1. SetContextPriority (parameter name: "kSetContextPriority")
2. SetRenderEngineType (parameter name: "kSetRenderEngineType")
3. CleanupMode (parameter name: "kCleanupMode")
4. DataSpace (parameter name: "kDataSpace")
5. ReadBufferUsage(parameter name: "kReadBufferUsage")
6. WriteBufferUsage(parameter name: "kWriteBufferUsage")
7. RenderBufferUsage(parameter name: "kRenderBufferUsage")

| Parameter| Valid Values| Configured Value|
|------------- |-------------| ----- |
|`kSetContextPriority`| 0. `RenderEngine::ContextPriority::LOW`<br/>1. `RenderEngine::ContextPriority::MEDIUM`<br/>2. `RenderEngine::ContextPriority::HIGH` |Value obtained from FuzzedDataProvider|
|`kSetRenderEngineType`| 0. `RenderEngine::RenderEngineType::GLES`<br/>1. `RenderEngine::RenderEngineType::THREADED`|Value obtained from FuzzedDataProvider|
|`kCleanupMode`| 0. `RenderEngine::CleanupMode::CLEAN_OUTPUT_RESOURCES`<br/>1. `RenderEngine::CleanupMode::CLEAN_ALL`|Value obtained from FuzzedDataProvider|
|`kDataSpace`| 0. `ui::Dataspace::UNKNOWN`<br/>1. `ui::Dataspace::ARBITRARY`<br/>2. `ui::Dataspace::STANDARD_SHIFT`<br/>3. `ui::Dataspace::STANDARD_MASK`<br/>4. `ui::Dataspace::STANDARD_UNSPECIFIED`<br/>5. `ui::Dataspace::STANDARD_BT709`<br/>6. `ui::Dataspace::STANDARD_BT601_625`<br/>7. `ui::Dataspace::STANDARD_BT601_625_UNADJUSTED`<br/>8. `ui::Dataspace::STANDARD_BT601_525`<br/>9. `ui::Dataspace::STANDARD_BT601_525_UNADJUSTED`<br/>10. `ui::Dataspace::STANDARD_BT2020`<br/>11. `ui::Dataspace::STANDARD_BT2020_CONSTANT_LUMINANCE`<br/>12. `ui::Dataspace::STANDARD_BT470M`<br/>13. `ui::Dataspace::STANDARD_FILM`<br/>14. `ui::Dataspace::STANDARD_DCI_P3`<br/>15. `ui::Dataspace::STANDARD_ADOBE_RGB`<br/>16. `ui::Dataspace::TRANSFER_SHIFT`<br/>17. `ui::Dataspace::TRANSFER_MASK`<br/>18. `ui::Dataspace::TRANSFER_UNSPECIFIED`<br/>19. `ui::Dataspace::TRANSFER_LINEAR`<br/>20. `ui::Dataspace::TRANSFER_SRGB`<br/>21. `ui::Dataspace::TRANSFER_SMPTE_170M`<br/>22. `ui::Dataspace::TRANSFER_GAMMA2_2`<br/>23. `ui::Dataspace::TRANSFER_GAMMA2_6`<br/>24. `ui::Dataspace::TRANSFER_GAMMA2_8`<br/>25. `ui::Dataspace::TRANSFER_ST2084`<br/>26. `ui::Dataspace::TRANSFER_HLG`<br/>27. `ui::Dataspace::RANGE_SHIFT`<br/>28. `ui::Dataspace::RANGE_MASK`<br/>29. `ui::Dataspace::RANGE_UNSPECIFIED`<br/>30. `ui::Dataspace::RANGE_FULL`<br/>31. `ui::Dataspace::RANGE_LIMITED`<br/>32. `ui::Dataspace::RANGE_EXTENDED`<br/>33. `ui::Dataspace::SRGB_LINEAR`<br/>34. `ui::Dataspace::V0_SRGB_LINEAR`<br/>35. `ui::Dataspace::V0_SCRGB_LINEAR`<br/>36. `ui::Dataspace::SRGB`<br/>37. `ui::Dataspace::V0_SRGB`<br/>38. `ui::Dataspace::V0_SCRGB`<br/>39. `ui::Dataspace::JFIF`<br/>40. `ui::Dataspace::V0_JFIF`<br/>41. `ui::Dataspace::BT601_625`<br/>42. `ui::Dataspace::V0_BT601_625`<br/>43. `ui::Dataspace::BT601_525`<br/>44. `ui::Dataspace::V0_BT601_525`<br/>45. `ui::Dataspace::BT709`<br/>46. `ui::Dataspace::V0_BT709`<br/>47. `ui::Dataspace::DCI_P3_LINEAR`<br/>48. `ui::Dataspace::DCI_P3`<br/>49. `ui::Dataspace::DISPLAY_P3_LINEAR`<br/>50. `ui::Dataspace::DISPLAY_P3`<br/>51. `ui::Dataspace::ADOBE_RGB`<br/>52. `ui::Dataspace::BT2020_LINEAR`<br/>53. `ui::Dataspace::BT2020`<br/>54. `ui::Dataspace::BT2020_PQ`<br/>55. `ui::Dataspace::DEPTH`<br/>56. `ui::Dataspace::SENSOR`<br/>57. `ui::Dataspace::BT2020_ITU`<br/>58. `ui::Dataspace::BT2020_ITU_PQ`<br/>59. `ui::Dataspace::BT2020_ITU_HLG`<br/>60. `ui::Dataspace::BT2020_HLG`<br/>61. `ui::Dataspace::DISPLAY_BT2020`<br/>62. `ui::Dataspace::DYNAMIC_DEPTH`<br/>63. `ui::Dataspace::JPEG_APP_SEGMENTS`<br/>64. `ui::Dataspace::HEIF`|Value obtained from FuzzedDataProvider|
|`kReadBufferUsage`| 0. `GRALLOC_USAGE_SW_READ_NEVER`<br/>1. `GRALLOC_USAGE_SW_READ_RARELY`<br/>2. `GRALLOC_USAGE_SW_READ_OFTEN`<br/>3. `GRALLOC_USAGE_SW_READ_MASK`|Value obtained from FuzzedDataProvider|
|`kWriteBufferUsage`| 0. `GRALLOC_USAGE_SW_WRITE_NEVER`<br/>1. `GRALLOC_USAGE_SW_WRITE_RARELY`<br/>2. `GRALLOC_USAGE_SW_WRITE_OFTEN`<br/>3. `GRALLOC_USAGE_SW_WRITE_MASK`|Value obtained from FuzzedDataProvider|
|`kRenderBufferUsage`| 0. `GRALLOC_USAGE_HW_TEXTURE`<br/>1. `GRALLOC_USAGE_HW_RENDER`<br/>2. `GRALLOC_USAGE_HW_2D`<br/>3. `GRALLOC_USAGE_HW_COMPOSER`<br/>4. `GRALLOC_USAGE_HW_FB`<br/>5. `GRALLOC_USAGE_EXTERNAL_DISP`<br/>6. `GRALLOC_USAGE_PROTECTED`<br/>7. `GRALLOC_USAGE_CURSOR`<br/>8. `GRALLOC_USAGE_HW_VIDEO_ENCODER`<br/>9. `GRALLOC_USAGE_HW_CAMERA_WRITE`<br/>10. `GRALLOC_USAGE_HW_CAMERA_READ`<br/>11. `GRALLOC_USAGE_HW_CAMERA_ZSL`<br/>12. `GRALLOC_USAGE_HW_CAMERA_MASK`<br/>13. `GRALLOC_USAGE_HW_MASK`<br/>14. `GRALLOC_USAGE_RENDERSCRIPT`<br/>15. `GRALLOC_USAGE_FOREIGN_BUFFERS`<br/>16. `GRALLOC_USAGE_HW_IMAGE_ENCODER`|Value obtained from FuzzedDataProvider|



#### Steps to run
1. Build the fuzzer
```
  $ mm -j$(nproc) libstagefright_renderfright_fuzzer
```
2. Run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/libstagefright_renderfright_fuzzer/libstagefright_renderfright_fuzzer
```
