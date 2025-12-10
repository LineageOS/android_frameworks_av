/*
* Copyright 2024 The Android Open Source Project
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#define LOG_TAG "SharedSessionConfigUtilsTest"

#include <android/hardware_buffer.h>
#include <camera/camera2/OutputConfiguration.h>
#include <system/camera_metadata.h>
#include <system/graphics.h>
#include <aidl/android/hardware/graphics/common/PixelFormat.h>

#include <gtest/gtest.h>
#include "../config/SharedSessionConfigUtils.h"
#include <tinyxml2.h>

using namespace android;
using namespace tinyxml2;
using AidlPixelFormat = aidl::android::hardware::graphics::common::PixelFormat;

// Helper function to create an XML element with text
XMLElement* CreateXMLElement(XMLDocument& doc, const char* elementName, const char* text) {
    XMLElement* elem = doc.NewElement(elementName);
    if (text != nullptr) {
        elem->SetText(text);
    }
    doc.InsertEndChild(elem);
    return elem;
}

// Test for SharedSessionConfigUtils::toString
TEST(SharedSessionConfigUtilsTest, ToStringTest) {
    EXPECT_STREQ(SharedSessionConfigUtils::toString(ErrorCode::STATUS_OK), "STATUS_OK");
    EXPECT_STREQ(SharedSessionConfigUtils::toString(ErrorCode::ERROR_READ_CONFIG_FILE),
                 "ERROR_READ_CONFIG_FILE");
    EXPECT_STREQ(SharedSessionConfigUtils::toString(ErrorCode::ERROR_CONFIG_FILE_FORMAT),
                 "ERROR_CONFIG_FILE_FORMAT");
    EXPECT_STREQ(SharedSessionConfigUtils::toString(
                         ErrorCode::ERROR_CONFIG_READER_UNINITIALIZED),
                 "ERROR_CONFIG_READER_UNINITIALIZED");
    EXPECT_STREQ(SharedSessionConfigUtils::toString(ErrorCode::ERROR_BAD_PARAMETER),
                 "ERROR_BAD_PARAMETER");

    // Test default case (unknown ErrorCode)
    EXPECT_STREQ(SharedSessionConfigUtils::toString(static_cast<ErrorCode>(999)), "");
}

// Test for SharedSessionConfigUtils::getColorSpaceFromStr
TEST(SharedSessionConfigUtilsTest, GetColorSpaceFromStrTest) {
    int32_t colorSpace;
    // Test with nullptr
    EXPECT_EQ(SharedSessionConfigUtils::getColorSpaceFromStr(nullptr, &colorSpace),
              ErrorCode::STATUS_OK);
    EXPECT_EQ(colorSpace, ANDROID_REQUEST_AVAILABLE_COLOR_SPACE_PROFILES_MAP_UNSPECIFIED);

    // Test with empty string
    EXPECT_EQ(SharedSessionConfigUtils::getColorSpaceFromStr("", &colorSpace),
              ErrorCode::STATUS_OK);
    EXPECT_EQ(colorSpace, ANDROID_REQUEST_AVAILABLE_COLOR_SPACE_PROFILES_MAP_UNSPECIFIED);

    // Test with valid strings
    struct {
        std::string input;
        int expected;
    } testCases[] = {
            {std::to_string(ANDROID_REQUEST_AVAILABLE_COLOR_SPACE_PROFILES_MAP_UNSPECIFIED),
             ANDROID_REQUEST_AVAILABLE_COLOR_SPACE_PROFILES_MAP_UNSPECIFIED},
            {std::to_string(ANDROID_REQUEST_AVAILABLE_COLOR_SPACE_PROFILES_MAP_SRGB),
             ANDROID_REQUEST_AVAILABLE_COLOR_SPACE_PROFILES_MAP_SRGB},
            {std::to_string(ANDROID_REQUEST_AVAILABLE_COLOR_SPACE_PROFILES_MAP_DISPLAY_P3),
             ANDROID_REQUEST_AVAILABLE_COLOR_SPACE_PROFILES_MAP_DISPLAY_P3},
            {std::to_string(ANDROID_REQUEST_AVAILABLE_COLOR_SPACE_PROFILES_MAP_BT2020_HLG),
             ANDROID_REQUEST_AVAILABLE_COLOR_SPACE_PROFILES_MAP_BT2020_HLG}
    };

    for (const auto& testCase : testCases) {
        EXPECT_EQ(SharedSessionConfigUtils::getColorSpaceFromStr(testCase.input.c_str(),
                                                                 &colorSpace),
                  ErrorCode::STATUS_OK);
        EXPECT_EQ(colorSpace, testCase.expected);
    }

    // Test with invalid string
    EXPECT_EQ(SharedSessionConfigUtils::getColorSpaceFromStr("-99", &colorSpace),
              ErrorCode::ERROR_CONFIG_FILE_FORMAT);
}

// Test for SharedSessionConfigUtils::getSurfaceTypeFromXml
TEST(SharedSessionConfigUtilsTest, GetSurfaceTypeFromXmlTest) {
    int64_t surfaceType;

    // Test with nullptr XML element
    EXPECT_EQ(SharedSessionConfigUtils::getSurfaceTypeFromXml(nullptr, &surfaceType),
              ErrorCode::ERROR_CONFIG_FILE_FORMAT);

    // Test with empty text
    XMLDocument doc;
    XMLElement* emptyElem = CreateXMLElement(doc, "surfaceType", "");
    EXPECT_EQ(SharedSessionConfigUtils::getSurfaceTypeFromXml(emptyElem, &surfaceType),
              ErrorCode::ERROR_CONFIG_FILE_FORMAT);

    // Test with valid surface types
    struct {
        std::string input;
        int expected;
    } testCases[] = {
            {std::to_string(OutputConfiguration::SURFACE_TYPE_SURFACE_VIEW),
             OutputConfiguration::SURFACE_TYPE_SURFACE_VIEW},
            {std::to_string(OutputConfiguration::SURFACE_TYPE_SURFACE_TEXTURE),
             OutputConfiguration::SURFACE_TYPE_SURFACE_TEXTURE},
            {std::to_string(OutputConfiguration::SURFACE_TYPE_MEDIA_RECORDER),
             OutputConfiguration::SURFACE_TYPE_MEDIA_RECORDER},
            {std::to_string(OutputConfiguration::SURFACE_TYPE_MEDIA_CODEC),
             OutputConfiguration::SURFACE_TYPE_MEDIA_CODEC},
            {std::to_string(OutputConfiguration::SURFACE_TYPE_IMAGE_READER),
             OutputConfiguration::SURFACE_TYPE_IMAGE_READER}
    };

    for (const auto& testCase : testCases) {
        XMLElement* elem = CreateXMLElement(doc, "surfaceType", testCase.input.c_str());
        EXPECT_EQ(SharedSessionConfigUtils::getSurfaceTypeFromXml(elem, &surfaceType),
                  ErrorCode::STATUS_OK);
        EXPECT_EQ(surfaceType, testCase.expected);
    }

    // Test with invalid surface type
    XMLElement* invalidElem = CreateXMLElement(doc, "surfaceType", "-99");
    EXPECT_EQ(SharedSessionConfigUtils::getSurfaceTypeFromXml(invalidElem, &surfaceType),
              ErrorCode::ERROR_CONFIG_FILE_FORMAT);
}

// Test for SharedSessionConfigUtils::getWidthFromXml
TEST(SharedSessionConfigUtilsTest, GetWidthFromXmlTest) {
    int64_t width;

    // Test with nullptr XML element
    EXPECT_EQ(SharedSessionConfigUtils::getWidthFromXml(nullptr, &width),
              ErrorCode::ERROR_CONFIG_FILE_FORMAT);

    XMLDocument doc;
    // Test with empty text
    XMLElement* emptyElem = CreateXMLElement(doc, "width", "");
    EXPECT_EQ(SharedSessionConfigUtils::getWidthFromXml(emptyElem, &width),
              ErrorCode::ERROR_CONFIG_FILE_FORMAT);

    // Test with valid width
    XMLElement* validElem = CreateXMLElement(doc, "width", "1920");
    EXPECT_EQ(SharedSessionConfigUtils::getWidthFromXml(validElem, &width),
              ErrorCode::STATUS_OK);
    EXPECT_EQ(width, 1920);

    // Test with invalid width (negative)
    XMLElement* invalidWidthElem = CreateXMLElement(doc, "width", "-100");
    EXPECT_EQ(SharedSessionConfigUtils::getWidthFromXml(invalidWidthElem, &width),
              ErrorCode::STATUS_OK);
    EXPECT_EQ(width, -100); // The method logs an error but still returns STATUS_OK

    // Test with non-numeric width
    XMLElement* nonNumericElem = CreateXMLElement(doc, "width", "abc");
    EXPECT_EQ(SharedSessionConfigUtils::getWidthFromXml(nonNumericElem, &width),
              ErrorCode::STATUS_OK);
    EXPECT_EQ(width, 0); // std::atoi returns 0 for non-numeric strings
}

// Test for SharedSessionConfigUtils::getHeightFromXml
TEST(SharedSessionConfigUtilsTest, GetHeightFromXmlTest) {
    int64_t height;

    XMLDocument doc;
    // Test with nullptr XML element
    EXPECT_EQ(SharedSessionConfigUtils::getHeightFromXml(nullptr, &height),
              ErrorCode::ERROR_CONFIG_FILE_FORMAT);

    // Test with empty text
    XMLElement* emptyElem = CreateXMLElement(doc, "height", "");
    EXPECT_EQ(SharedSessionConfigUtils::getHeightFromXml(emptyElem, &height),
              ErrorCode::ERROR_CONFIG_FILE_FORMAT);

    // Test with valid height
    XMLElement* validElem = CreateXMLElement(doc, "height", "1080");
    EXPECT_EQ(SharedSessionConfigUtils::getHeightFromXml(validElem, &height), ErrorCode::STATUS_OK);
    EXPECT_EQ(height, 1080);

    // Test with invalid height (zero)
    XMLElement* invalidHeightElem = CreateXMLElement(doc, "height", "0");
    EXPECT_EQ(SharedSessionConfigUtils::getHeightFromXml(invalidHeightElem, &height),
              ErrorCode::STATUS_OK);
    EXPECT_EQ(height, 0); // The method logs an error but still returns STATUS_OK

    // Test with non-numeric height
    XMLElement* nonNumericElem = CreateXMLElement(doc, "height", "xyz");
    EXPECT_EQ(SharedSessionConfigUtils::getHeightFromXml(nonNumericElem, &height),
              ErrorCode::STATUS_OK);
    EXPECT_EQ(height, 0); // std::atoi returns 0 for non-numeric strings
}

// Test for SharedSessionConfigUtils::getPhysicalCameraIdFromXml
TEST(SharedSessionConfigUtilsTest, GetPhysicalCameraIdFromXmlTest) {
    std::string physicalCameraId;

    // Test with nullptr XML element
    EXPECT_EQ(SharedSessionConfigUtils::getPhysicalCameraIdFromXml(nullptr, &physicalCameraId),
              ErrorCode::STATUS_OK);
    EXPECT_EQ(physicalCameraId, "");

    XMLDocument doc;
    // Test with empty text
    XMLElement* emptyElem = CreateXMLElement(doc, "physicalCameraId", "");
    EXPECT_EQ(SharedSessionConfigUtils::getPhysicalCameraIdFromXml(emptyElem, &physicalCameraId),
              ErrorCode::STATUS_OK);
    EXPECT_EQ(physicalCameraId, "");

    // Test with valid physical camera ID
    XMLElement* validElem = CreateXMLElement(doc, "physicalCameraId", "physical_camera_1");
    EXPECT_EQ(SharedSessionConfigUtils::getPhysicalCameraIdFromXml(validElem, &physicalCameraId),
              ErrorCode::STATUS_OK);
    EXPECT_EQ(physicalCameraId, "physical_camera_1");
}

// Test for SharedSessionConfigUtils::getStreamUseCaseFromXml
TEST(SharedSessionConfigUtilsTest, GetStreamUseCaseFromXmlTest) {
    int64_t streamUseCase;

    // Test with nullptr XML element
    EXPECT_EQ(SharedSessionConfigUtils::getStreamUseCaseFromXml(nullptr, &streamUseCase),
              ErrorCode::STATUS_OK);
    EXPECT_EQ(streamUseCase, ANDROID_SCALER_AVAILABLE_STREAM_USE_CASES_DEFAULT);

    XMLDocument doc;
    // Test with empty text
    XMLElement* emptyElem = CreateXMLElement(doc, "streamUseCase", "");
    EXPECT_EQ(SharedSessionConfigUtils::getStreamUseCaseFromXml(emptyElem, &streamUseCase),
              ErrorCode::STATUS_OK);
    EXPECT_EQ(streamUseCase, ANDROID_SCALER_AVAILABLE_STREAM_USE_CASES_DEFAULT);

    // Test with valid stream use cases
    struct {
        std::string input;
        int64_t expected;
    } testCases[] = {
            {std::to_string(ANDROID_SCALER_AVAILABLE_STREAM_USE_CASES_DEFAULT),
             ANDROID_SCALER_AVAILABLE_STREAM_USE_CASES_DEFAULT},
            {std::to_string(ANDROID_SCALER_AVAILABLE_STREAM_USE_CASES_PREVIEW),
             ANDROID_SCALER_AVAILABLE_STREAM_USE_CASES_PREVIEW},
            {std::to_string(ANDROID_SCALER_AVAILABLE_STREAM_USE_CASES_STILL_CAPTURE),
             ANDROID_SCALER_AVAILABLE_STREAM_USE_CASES_STILL_CAPTURE},
            {std::to_string(ANDROID_SCALER_AVAILABLE_STREAM_USE_CASES_VIDEO_RECORD),
             ANDROID_SCALER_AVAILABLE_STREAM_USE_CASES_VIDEO_RECORD},
            {std::to_string(ANDROID_SCALER_AVAILABLE_STREAM_USE_CASES_PREVIEW_VIDEO_STILL),
             ANDROID_SCALER_AVAILABLE_STREAM_USE_CASES_PREVIEW_VIDEO_STILL},
            {std::to_string(ANDROID_SCALER_AVAILABLE_STREAM_USE_CASES_VIDEO_CALL),
             ANDROID_SCALER_AVAILABLE_STREAM_USE_CASES_VIDEO_CALL},
            {std::to_string(ANDROID_SCALER_AVAILABLE_STREAM_USE_CASES_CROPPED_RAW),
             ANDROID_SCALER_AVAILABLE_STREAM_USE_CASES_CROPPED_RAW},
            {std::to_string(ANDROID_SCALER_AVAILABLE_STREAM_USE_CASES_VENDOR_START),
             ANDROID_SCALER_AVAILABLE_STREAM_USE_CASES_VENDOR_START}
    };

    for (const auto& testCase : testCases) {
        XMLElement* elem = CreateXMLElement(doc, "streamUseCase", testCase.input.c_str());
        EXPECT_EQ(SharedSessionConfigUtils::getStreamUseCaseFromXml(elem, &streamUseCase),
                  ErrorCode::STATUS_OK);
        EXPECT_EQ(streamUseCase, testCase.expected);
    }

    // Test with invalid stream use case
    XMLElement* invalidElem = CreateXMLElement(doc, "streamUseCase", "-99");
    EXPECT_EQ(SharedSessionConfigUtils::getStreamUseCaseFromXml(invalidElem, &streamUseCase),
              ErrorCode::ERROR_CONFIG_FILE_FORMAT);
}

// Test for SharedSessionConfigUtils::getTimestampBaseFromXml
TEST(SharedSessionConfigUtilsTest, GetTimestampBaseFromXmlTest) {
    int64_t timestampBase;

    // Test with nullptr XML element
    EXPECT_EQ(SharedSessionConfigUtils::getTimestampBaseFromXml(nullptr, &timestampBase),
              ErrorCode::STATUS_OK);
    EXPECT_EQ(timestampBase, OutputConfiguration::TIMESTAMP_BASE_DEFAULT);

    XMLDocument doc;
    // Test with empty text
    XMLElement* emptyElem = CreateXMLElement(doc, "timestampBase", "");
    EXPECT_EQ(SharedSessionConfigUtils::getTimestampBaseFromXml(emptyElem, &timestampBase),
              ErrorCode::STATUS_OK);
    EXPECT_EQ(timestampBase, OutputConfiguration::TIMESTAMP_BASE_DEFAULT);

    // Test with valid timestamp bases
    struct {
        std::string input;
        int expected;
    } testCases[] = {
            {std::to_string(OutputConfiguration::TIMESTAMP_BASE_DEFAULT),
             OutputConfiguration::TIMESTAMP_BASE_DEFAULT},
            {std::to_string(OutputConfiguration::TIMESTAMP_BASE_SENSOR),
             OutputConfiguration::TIMESTAMP_BASE_SENSOR},
            {std::to_string(OutputConfiguration::TIMESTAMP_BASE_MONOTONIC),
             OutputConfiguration::TIMESTAMP_BASE_MONOTONIC},
            {std::to_string(OutputConfiguration::TIMESTAMP_BASE_REALTIME),
             OutputConfiguration::TIMESTAMP_BASE_REALTIME},
            {std::to_string(OutputConfiguration::TIMESTAMP_BASE_CHOREOGRAPHER_SYNCED),
             OutputConfiguration::TIMESTAMP_BASE_CHOREOGRAPHER_SYNCED},
            {std::to_string(OutputConfiguration::TIMESTAMP_BASE_MAX),
             OutputConfiguration::TIMESTAMP_BASE_MAX}
    };

    for (const auto& testCase : testCases) {
        XMLElement* elem = CreateXMLElement(doc, "timestampBase", testCase.input.c_str());
        EXPECT_EQ(SharedSessionConfigUtils::getTimestampBaseFromXml(elem, &timestampBase),
                  ErrorCode::STATUS_OK);
        EXPECT_EQ(timestampBase, testCase.expected);
    }

    // Test with invalid timestamp base
    XMLElement* invalidElem = CreateXMLElement(doc, "timestampBase", "-99");
    EXPECT_EQ(SharedSessionConfigUtils::getTimestampBaseFromXml(invalidElem, &timestampBase),
              ErrorCode::ERROR_CONFIG_FILE_FORMAT);
}

// Test for SharedSessionConfigUtils::getMirrorModeFromXml
TEST(SharedSessionConfigUtilsTest, GetMirrorModeFromXmlTest) {
    int64_t mirrorMode;

    // Test with nullptr XML element
    EXPECT_EQ(SharedSessionConfigUtils::getMirrorModeFromXml(nullptr, &mirrorMode),
              ErrorCode::STATUS_OK);
    EXPECT_EQ(mirrorMode, OutputConfiguration::MIRROR_MODE_AUTO);

    XMLDocument doc;
    // Test with empty text
    XMLElement* emptyElem = CreateXMLElement(doc, "mirrorMode", "");
    EXPECT_EQ(SharedSessionConfigUtils::getMirrorModeFromXml(emptyElem, &mirrorMode),
              ErrorCode::STATUS_OK);
    EXPECT_EQ(mirrorMode, OutputConfiguration::MIRROR_MODE_AUTO);

    // Test with valid mirror modes
    struct {
        std::string input;
        int expected;
    } testCases[] = {
            {std::to_string(OutputConfiguration::MIRROR_MODE_AUTO),
             OutputConfiguration::MIRROR_MODE_AUTO},
            {std::to_string(OutputConfiguration::MIRROR_MODE_NONE),
             OutputConfiguration::MIRROR_MODE_NONE},
            {std::to_string(OutputConfiguration::MIRROR_MODE_H),
             OutputConfiguration::MIRROR_MODE_H},
            {std::to_string(OutputConfiguration::MIRROR_MODE_V),
             OutputConfiguration::MIRROR_MODE_V}
    };

    for (const auto& testCase : testCases) {
        XMLElement* elem = CreateXMLElement(doc, "mirrorMode", testCase.input.c_str());
        EXPECT_EQ(SharedSessionConfigUtils::getMirrorModeFromXml(elem, &mirrorMode),
                  ErrorCode::STATUS_OK);
        EXPECT_EQ(mirrorMode, testCase.expected);
    }

    // Test with invalid mirror mode
    XMLElement* invalidElem = CreateXMLElement(doc, "mirrorMode", "-99");
    EXPECT_EQ(SharedSessionConfigUtils::getMirrorModeFromXml(invalidElem, &mirrorMode),
              ErrorCode::ERROR_CONFIG_FILE_FORMAT);
}

// Test for SharedSessionConfigUtils::getUseReadoutTimestampFromXml
TEST(SharedSessionConfigUtilsTest, GetUseReadoutTimestampFromXmlTest) {
    bool useReadoutTimestamp;

    // Test with nullptr XML element
    EXPECT_EQ(SharedSessionConfigUtils::getUseReadoutTimestampFromXml(nullptr,
                                                                      &useReadoutTimestamp),
              ErrorCode::STATUS_OK);
    EXPECT_FALSE(useReadoutTimestamp);

    XMLDocument doc;
    // Test with empty text (should default to false)
    XMLElement* emptyElem = CreateXMLElement(doc, "useReadoutTimestamp", "");
    EXPECT_EQ(SharedSessionConfigUtils::getUseReadoutTimestampFromXml(emptyElem,
                                                                      &useReadoutTimestamp),
              ErrorCode::STATUS_OK);
    EXPECT_FALSE(useReadoutTimestamp);

    // Test with "true"
    XMLElement* trueElem = CreateXMLElement(doc, "useReadoutTimestamp", "1");
    EXPECT_EQ(SharedSessionConfigUtils::getUseReadoutTimestampFromXml(trueElem,
                                                                      &useReadoutTimestamp),
              ErrorCode::STATUS_OK);
    EXPECT_TRUE(useReadoutTimestamp);

    // Test with "false"
    XMLElement* falseElem = CreateXMLElement(doc, "useReadoutTimestamp", "0");
    EXPECT_EQ(SharedSessionConfigUtils::getUseReadoutTimestampFromXml(falseElem,
                                                                      &useReadoutTimestamp),
              ErrorCode::STATUS_OK);
    EXPECT_FALSE(useReadoutTimestamp);

    // Test with invalid string
    XMLElement* invalidElem = CreateXMLElement(doc, "useReadoutTimestamp", "-99");
    EXPECT_EQ(SharedSessionConfigUtils::getUseReadoutTimestampFromXml(invalidElem,
                                                                      &useReadoutTimestamp),
              ErrorCode::ERROR_CONFIG_FILE_FORMAT);
}

// Test for SharedSessionConfigUtils::getFormatFromXml
TEST(SharedSessionConfigUtilsTest, GetFormatFromXmlTest) {
    int64_t format;

    int64_t surfaceType = OutputConfiguration::SURFACE_TYPE_SURFACE_TEXTURE;
    // Test with nullptr XML element with surfaceType != IMAGE_READER
    EXPECT_EQ(SharedSessionConfigUtils::getFormatFromXml(nullptr, &format, surfaceType),
              ErrorCode::STATUS_OK);
    EXPECT_EQ(format, HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED);

    surfaceType = OutputConfiguration::SURFACE_TYPE_IMAGE_READER;
    // Test with nullptr XML element with surfaceType == IMAGE_READER
    EXPECT_EQ(SharedSessionConfigUtils::getFormatFromXml(nullptr, &format, surfaceType),
              ErrorCode::ERROR_CONFIG_FILE_FORMAT);

    XMLDocument doc;
    // Test with empty text
    XMLElement* emptyElem = CreateXMLElement(doc, "format", "");
    EXPECT_EQ(SharedSessionConfigUtils::getFormatFromXml(emptyElem, &format, surfaceType),
              ErrorCode::ERROR_CONFIG_FILE_FORMAT);

    // Test with valid formats
    struct {
        std::string input;
        int expected;
    } testCases[] = {
            {std::to_string(HAL_PIXEL_FORMAT_RGBA_8888), HAL_PIXEL_FORMAT_RGBA_8888},
            {std::to_string(HAL_PIXEL_FORMAT_RGBX_8888), HAL_PIXEL_FORMAT_RGBX_8888},
            {std::to_string(HAL_PIXEL_FORMAT_RGB_888), HAL_PIXEL_FORMAT_RGB_888},
            {std::to_string(HAL_PIXEL_FORMAT_RGB_565), HAL_PIXEL_FORMAT_RGB_565},
            {std::to_string(HAL_PIXEL_FORMAT_BGRA_8888), HAL_PIXEL_FORMAT_BGRA_8888},
            {std::to_string(HAL_PIXEL_FORMAT_YCBCR_422_SP), HAL_PIXEL_FORMAT_YCBCR_422_SP},
            {std::to_string(HAL_PIXEL_FORMAT_YCRCB_420_SP), HAL_PIXEL_FORMAT_YCRCB_420_SP},
            {std::to_string(HAL_PIXEL_FORMAT_YCBCR_422_I), HAL_PIXEL_FORMAT_YCBCR_422_I},
            {std::to_string(HAL_PIXEL_FORMAT_RGBA_FP16), HAL_PIXEL_FORMAT_RGBA_FP16},
            {std::to_string(HAL_PIXEL_FORMAT_RAW16), HAL_PIXEL_FORMAT_RAW16},
            {std::to_string(HAL_PIXEL_FORMAT_BLOB), HAL_PIXEL_FORMAT_BLOB},
            {std::to_string(HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED),
             HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED},
            {std::to_string(HAL_PIXEL_FORMAT_YCBCR_420_888), HAL_PIXEL_FORMAT_YCBCR_420_888},
            {std::to_string(HAL_PIXEL_FORMAT_RAW_OPAQUE), HAL_PIXEL_FORMAT_RAW_OPAQUE},
            {std::to_string(HAL_PIXEL_FORMAT_RAW10), HAL_PIXEL_FORMAT_RAW10},
            {std::to_string(HAL_PIXEL_FORMAT_RAW12), HAL_PIXEL_FORMAT_RAW12},
            {std::to_string(static_cast<int64_t>(AidlPixelFormat::RAW14)),
                static_cast<int64_t>(AidlPixelFormat::RAW14)},
            {std::to_string(HAL_PIXEL_FORMAT_RGBA_1010102), HAL_PIXEL_FORMAT_RGBA_1010102},
            {std::to_string(HAL_PIXEL_FORMAT_Y8), HAL_PIXEL_FORMAT_Y8},
            {std::to_string(HAL_PIXEL_FORMAT_Y16), HAL_PIXEL_FORMAT_Y16},
            {std::to_string(HAL_PIXEL_FORMAT_YV12), HAL_PIXEL_FORMAT_YV12},
            {std::to_string(HAL_PIXEL_FORMAT_DEPTH_16), HAL_PIXEL_FORMAT_DEPTH_16},
            {std::to_string(HAL_PIXEL_FORMAT_DEPTH_24), HAL_PIXEL_FORMAT_DEPTH_24},
            {std::to_string(HAL_PIXEL_FORMAT_DEPTH_24_STENCIL_8),
             HAL_PIXEL_FORMAT_DEPTH_24_STENCIL_8},
            {std::to_string(HAL_PIXEL_FORMAT_DEPTH_32F), HAL_PIXEL_FORMAT_DEPTH_32F},
            {std::to_string(HAL_PIXEL_FORMAT_DEPTH_32F_STENCIL_8),
             HAL_PIXEL_FORMAT_DEPTH_32F_STENCIL_8},
            {std::to_string(HAL_PIXEL_FORMAT_STENCIL_8), HAL_PIXEL_FORMAT_STENCIL_8},
            {std::to_string(HAL_PIXEL_FORMAT_YCBCR_P010), HAL_PIXEL_FORMAT_YCBCR_P010},
            {std::to_string(HAL_PIXEL_FORMAT_HSV_888), HAL_PIXEL_FORMAT_HSV_888}
    };

    for (const auto& testCase : testCases) {
        XMLElement* elem = CreateXMLElement(doc, "format", testCase.input.c_str());
        EXPECT_EQ(SharedSessionConfigUtils::getFormatFromXml(elem, &format, surfaceType),
                  ErrorCode::STATUS_OK);
        EXPECT_EQ(format, testCase.expected);
    }

    // Test with invalid format
    XMLElement* invalidElem = CreateXMLElement(doc, "format", "-99");
    EXPECT_EQ(SharedSessionConfigUtils::getFormatFromXml(invalidElem, &format, surfaceType),
              ErrorCode::ERROR_CONFIG_FILE_FORMAT);
}

// Test for SharedSessionConfigUtils::getUsageFromXml
TEST(SharedSessionConfigUtilsTest, GetUsageFromXmlTest) {
    int64_t usage = 0;

    int64_t surfaceType = OutputConfiguration::SURFACE_TYPE_SURFACE_TEXTURE;
    // Test with nullptr XML element with surfaceType == SURFACE_TYPE_SURFACE_TEXTURE
    EXPECT_EQ(SharedSessionConfigUtils::getUsageFromXml(nullptr, &usage, surfaceType),
              ErrorCode::STATUS_OK);
    EXPECT_EQ(usage, static_cast<int64_t>(AHARDWAREBUFFER_USAGE_GPU_SAMPLED_IMAGE));

    // clear usage value
    usage = 0;
    surfaceType = OutputConfiguration::SURFACE_TYPE_SURFACE_VIEW;
    // Test with nullptr XML element with surfaceType == SURFACE_TYPE_SURFACE_VIEW
    EXPECT_EQ(SharedSessionConfigUtils::getUsageFromXml(nullptr, &usage, surfaceType),
              ErrorCode::STATUS_OK);
    EXPECT_EQ(usage, static_cast<int64_t>(AHARDWAREBUFFER_USAGE_GPU_SAMPLED_IMAGE
                                          | AHARDWAREBUFFER_USAGE_COMPOSER_OVERLAY));

    // clear usage value
    usage = 0;
    surfaceType = OutputConfiguration::SURFACE_TYPE_MEDIA_RECORDER;
    // Test with nullptr XML element with surfaceType == SURFACE_TYPE_MEDIA_RECORDER
    EXPECT_EQ(SharedSessionConfigUtils::getUsageFromXml(nullptr, &usage, surfaceType),
              ErrorCode::STATUS_OK);
    EXPECT_EQ(usage, static_cast<int64_t>(AHARDWAREBUFFER_USAGE_VIDEO_ENCODE));

    // clear usage value
    usage = 0;
    surfaceType = OutputConfiguration::SURFACE_TYPE_MEDIA_CODEC;
    // Test with nullptr XML element with surfaceType == SURFACE_TYPE_MEDIA_CODEC
    EXPECT_EQ(SharedSessionConfigUtils::getUsageFromXml(nullptr, &usage, surfaceType),
              ErrorCode::STATUS_OK);
    EXPECT_EQ(usage, static_cast<int64_t>(AHARDWAREBUFFER_USAGE_VIDEO_ENCODE));

    // clear usage value
    usage = 0;
    surfaceType = OutputConfiguration::SURFACE_TYPE_IMAGE_READER;
    // Test with nullptr XML element with surfaceType == IMAGE_READER
    EXPECT_EQ(SharedSessionConfigUtils::getUsageFromXml(nullptr, &usage, surfaceType),
              ErrorCode::STATUS_OK);
    EXPECT_EQ(usage, static_cast<int64_t>(AHARDWAREBUFFER_USAGE_CPU_READ_NEVER));


    // clear usage value
    usage = 0;
    XMLDocument doc;
    // Test with empty text
    XMLElement* emptyElem = CreateXMLElement(doc, "usage", "");
    EXPECT_EQ(SharedSessionConfigUtils::getUsageFromXml(emptyElem, &usage, surfaceType),
              ErrorCode::STATUS_OK);
    EXPECT_EQ(usage, static_cast<int64_t>(AHARDWAREBUFFER_USAGE_CPU_READ_NEVER));

    // clear usage value
    usage = 0;
    // Test with valid single usage
    XMLElement* singleUsageElem = CreateXMLElement(doc, "usage",
                                                   std::to_string(
                                                           AHARDWAREBUFFER_USAGE_CPU_READ_OFTEN)
                                                           .c_str());
    EXPECT_EQ(SharedSessionConfigUtils::getUsageFromXml(singleUsageElem, &usage, surfaceType),
              ErrorCode::STATUS_OK);
    EXPECT_EQ(usage, static_cast<int64_t>(AHARDWAREBUFFER_USAGE_CPU_READ_OFTEN));

    // clear usage value
    usage = 0;
    // Test with valid multiple usages
    XMLElement* multipleUsagesElem =
            CreateXMLElement(doc, "usage",
                             (std::to_string(AHARDWAREBUFFER_USAGE_CPU_READ_NEVER)
                                     + "|" + std::to_string(AHARDWAREBUFFER_USAGE_GPU_FRAMEBUFFER)
                                     + "|" + std::to_string(AHARDWAREBUFFER_USAGE_VIDEO_ENCODE))
                                     .c_str());
    EXPECT_EQ(SharedSessionConfigUtils::getUsageFromXml(multipleUsagesElem, &usage, surfaceType),
              ErrorCode::STATUS_OK);
    EXPECT_EQ(usage, static_cast<int64_t>(AHARDWAREBUFFER_USAGE_CPU_READ_NEVER
                                          | AHARDWAREBUFFER_USAGE_GPU_FRAMEBUFFER
                                          | AHARDWAREBUFFER_USAGE_VIDEO_ENCODE));

    // clear usage value
    usage = 0;
    // Test with invalid usage
    XMLElement* invalidUsageElem = CreateXMLElement(doc, "usage", "-99");
    EXPECT_EQ(SharedSessionConfigUtils::getUsageFromXml(invalidUsageElem, &usage, surfaceType),
              ErrorCode::ERROR_CONFIG_FILE_FORMAT);

    // clear usage value
    usage = 0;
    // Test with a mix of valid and invalid usages
    XMLElement* mixedUsageElem =
            CreateXMLElement(doc, "usage",
                             (std::to_string(AHARDWAREBUFFER_USAGE_CPU_READ_NEVER) + "|-99")
                                     .c_str());
    EXPECT_EQ(SharedSessionConfigUtils::getUsageFromXml(mixedUsageElem, &usage, surfaceType),
              ErrorCode::ERROR_CONFIG_FILE_FORMAT);
}

// Test for SharedSessionConfigUtils::getDataSpaceFromXml
TEST(SharedSessionConfigUtilsTest, GetDataSpaceFromXmlTest) {
    int64_t dataSpace;

    XMLDocument doc;
    // Test with nullptr XML element
    EXPECT_EQ(SharedSessionConfigUtils::getDataSpaceFromXml(nullptr, &dataSpace),
              ErrorCode::STATUS_OK);
    EXPECT_EQ(dataSpace, HAL_DATASPACE_UNKNOWN);

    // Test with empty text
    XMLElement* emptyElem = CreateXMLElement(doc, "dataSpace", "");
    EXPECT_EQ(SharedSessionConfigUtils::getDataSpaceFromXml(emptyElem, &dataSpace),
              ErrorCode::STATUS_OK);
    EXPECT_EQ(dataSpace, HAL_DATASPACE_UNKNOWN);

    // Test with valid data spaces
    struct {
        std::string input;
        int expected;
    } testCases[] = {
            {std::to_string(HAL_DATASPACE_UNKNOWN), HAL_DATASPACE_UNKNOWN},
            {std::to_string(HAL_DATASPACE_ARBITRARY), HAL_DATASPACE_ARBITRARY},
            {std::to_string(HAL_DATASPACE_STANDARD_UNSPECIFIED),
             HAL_DATASPACE_STANDARD_UNSPECIFIED},
            {std::to_string(HAL_DATASPACE_STANDARD_BT709), HAL_DATASPACE_STANDARD_BT709},
            {std::to_string(HAL_DATASPACE_STANDARD_BT601_625), HAL_DATASPACE_STANDARD_BT601_625},
            {std::to_string(HAL_DATASPACE_STANDARD_BT601_625_UNADJUSTED),
             HAL_DATASPACE_STANDARD_BT601_625_UNADJUSTED},
            {std::to_string(HAL_DATASPACE_STANDARD_BT601_525), HAL_DATASPACE_STANDARD_BT601_525},
            {std::to_string(HAL_DATASPACE_STANDARD_BT601_525_UNADJUSTED),
             HAL_DATASPACE_STANDARD_BT601_525_UNADJUSTED},
            {std::to_string(HAL_DATASPACE_STANDARD_BT2020), HAL_DATASPACE_STANDARD_BT2020},
            {std::to_string(HAL_DATASPACE_STANDARD_BT2020_CONSTANT_LUMINANCE),
             HAL_DATASPACE_STANDARD_BT2020_CONSTANT_LUMINANCE},
            {std::to_string(HAL_DATASPACE_STANDARD_BT470M), HAL_DATASPACE_STANDARD_BT470M},
            {std::to_string(HAL_DATASPACE_STANDARD_FILM), HAL_DATASPACE_STANDARD_FILM},
            {std::to_string(HAL_DATASPACE_STANDARD_DCI_P3), HAL_DATASPACE_STANDARD_DCI_P3},
            {std::to_string(HAL_DATASPACE_STANDARD_ADOBE_RGB), HAL_DATASPACE_STANDARD_ADOBE_RGB},
            {std::to_string(HAL_DATASPACE_TRANSFER_UNSPECIFIED),
             HAL_DATASPACE_TRANSFER_UNSPECIFIED},
            {std::to_string(HAL_DATASPACE_TRANSFER_LINEAR), HAL_DATASPACE_TRANSFER_LINEAR},
            {std::to_string(HAL_DATASPACE_TRANSFER_SRGB), HAL_DATASPACE_TRANSFER_SRGB},
            {std::to_string(HAL_DATASPACE_TRANSFER_SMPTE_170M), HAL_DATASPACE_TRANSFER_SMPTE_170M},
            {std::to_string(HAL_DATASPACE_TRANSFER_GAMMA2_2), HAL_DATASPACE_TRANSFER_GAMMA2_2},
            {std::to_string(HAL_DATASPACE_TRANSFER_GAMMA2_6), HAL_DATASPACE_TRANSFER_GAMMA2_6},
            {std::to_string(HAL_DATASPACE_TRANSFER_GAMMA2_8), HAL_DATASPACE_TRANSFER_GAMMA2_8},
            {std::to_string(HAL_DATASPACE_TRANSFER_ST2084), HAL_DATASPACE_TRANSFER_ST2084},
            {std::to_string(HAL_DATASPACE_TRANSFER_HLG), HAL_DATASPACE_TRANSFER_HLG},
            {std::to_string(HAL_DATASPACE_RANGE_UNSPECIFIED), HAL_DATASPACE_RANGE_UNSPECIFIED},
            {std::to_string(HAL_DATASPACE_RANGE_FULL), HAL_DATASPACE_RANGE_FULL},
            {std::to_string(HAL_DATASPACE_RANGE_LIMITED), HAL_DATASPACE_RANGE_LIMITED},
            {std::to_string(HAL_DATASPACE_RANGE_EXTENDED), HAL_DATASPACE_RANGE_EXTENDED},
            {std::to_string(HAL_DATASPACE_SRGB_LINEAR), HAL_DATASPACE_SRGB_LINEAR},
            {std::to_string(HAL_DATASPACE_V0_SRGB_LINEAR), HAL_DATASPACE_V0_SRGB_LINEAR},
            {std::to_string(HAL_DATASPACE_V0_SCRGB_LINEAR), HAL_DATASPACE_V0_SCRGB_LINEAR},
            {std::to_string(HAL_DATASPACE_SRGB), HAL_DATASPACE_SRGB},
            {std::to_string(HAL_DATASPACE_V0_SRGB), HAL_DATASPACE_V0_SRGB},
            {std::to_string(HAL_DATASPACE_V0_SCRGB), HAL_DATASPACE_V0_SCRGB},
            {std::to_string(HAL_DATASPACE_JFIF), HAL_DATASPACE_JFIF},
            {std::to_string(HAL_DATASPACE_V0_JFIF), HAL_DATASPACE_V0_JFIF},
            {std::to_string(HAL_DATASPACE_BT601_625), HAL_DATASPACE_BT601_625},
            {std::to_string(HAL_DATASPACE_V0_BT601_625), HAL_DATASPACE_V0_BT601_625},
            {std::to_string(HAL_DATASPACE_BT601_525), HAL_DATASPACE_BT601_525},
            {std::to_string(HAL_DATASPACE_V0_BT601_525), HAL_DATASPACE_V0_BT601_525},
            {std::to_string(HAL_DATASPACE_BT709), HAL_DATASPACE_BT709},
            {std::to_string(HAL_DATASPACE_V0_BT709), HAL_DATASPACE_V0_BT709},
            {std::to_string(HAL_DATASPACE_DCI_P3_LINEAR), HAL_DATASPACE_DCI_P3_LINEAR},
            {std::to_string(HAL_DATASPACE_DCI_P3), HAL_DATASPACE_DCI_P3},
            {std::to_string(HAL_DATASPACE_DISPLAY_P3_LINEAR), HAL_DATASPACE_DISPLAY_P3_LINEAR},
            {std::to_string(HAL_DATASPACE_DISPLAY_P3), HAL_DATASPACE_DISPLAY_P3},
            {std::to_string(HAL_DATASPACE_ADOBE_RGB), HAL_DATASPACE_ADOBE_RGB},
            {std::to_string(HAL_DATASPACE_BT2020_LINEAR), HAL_DATASPACE_BT2020_LINEAR},
            {std::to_string(HAL_DATASPACE_BT2020), HAL_DATASPACE_BT2020},
            {std::to_string(HAL_DATASPACE_BT2020_PQ), HAL_DATASPACE_BT2020_PQ},
            {std::to_string(HAL_DATASPACE_DEPTH), HAL_DATASPACE_DEPTH},
            {std::to_string(HAL_DATASPACE_SENSOR), HAL_DATASPACE_SENSOR}
    };

    for (const auto& testCase : testCases) {
        XMLElement* elem = CreateXMLElement(doc, "dataSpace", testCase.input.c_str());
        EXPECT_EQ(SharedSessionConfigUtils::getDataSpaceFromXml(elem, &dataSpace),
                  ErrorCode::STATUS_OK);
        EXPECT_EQ(dataSpace, testCase.expected);
    }

    // Test with invalid data space
    XMLElement* invalidElem = CreateXMLElement(doc, "dataSpace", "-99");
    EXPECT_EQ(SharedSessionConfigUtils::getDataSpaceFromXml(invalidElem, &dataSpace),
              ErrorCode::ERROR_CONFIG_FILE_FORMAT);
}
