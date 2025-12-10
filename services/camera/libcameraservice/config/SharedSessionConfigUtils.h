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

#ifndef ANDROID_SERVERS_CAMERA_SHAREDSESSIONCONFIGUTILS_H_
#define ANDROID_SERVERS_CAMERA_SHAREDSESSIONCONFIGUTILS_H_

#define SHARED_SESSION_FILE_PATH "system_ext/etc/"
#define SHARED_SESSION_FILE_NAME "shared_session_config.xml"

#include <android/hardware_buffer.h>
#include <camera/camera2/OutputConfiguration.h>
#include <system/camera_metadata.h>
#include <system/graphics.h>
#include <aidl/android/hardware/graphics/common/PixelFormat.h>

#include <set>
#include <string>
#include "tinyxml2.h"
#include <vector>

using tinyxml2::XMLElement;
using AidlPixelFormat = aidl::android::hardware::graphics::common::PixelFormat;
namespace android {

enum ErrorCode : uint8_t {
    // OK status.
    STATUS_OK = 0,

    // Error status. Cannot read the config file (config file missing or not
    // accessible)
    ERROR_READ_CONFIG_FILE = 1,

    // Error status. Config file format doesn't match.
    ERROR_CONFIG_FILE_FORMAT = 2,

    // Error status. Config reader hasn't been initialized.
    ERROR_CONFIG_READER_UNINITIALIZED = 3,

    // Error status. Bad parameter.
    ERROR_BAD_PARAMETER = 4,
};

inline const std::set<int64_t> VALID_COLOR_SPACES = {
        ANDROID_REQUEST_AVAILABLE_COLOR_SPACE_PROFILES_MAP_UNSPECIFIED,
        ANDROID_REQUEST_AVAILABLE_COLOR_SPACE_PROFILES_MAP_SRGB,
        ANDROID_REQUEST_AVAILABLE_COLOR_SPACE_PROFILES_MAP_DISPLAY_P3,
        ANDROID_REQUEST_AVAILABLE_COLOR_SPACE_PROFILES_MAP_BT2020_HLG,
};

inline const std::set<int64_t> VALID_SURFACE_TYPES = {
        OutputConfiguration::SURFACE_TYPE_SURFACE_VIEW,
        OutputConfiguration::SURFACE_TYPE_SURFACE_TEXTURE,
        OutputConfiguration::SURFACE_TYPE_MEDIA_RECORDER,
        OutputConfiguration::SURFACE_TYPE_MEDIA_CODEC,
        OutputConfiguration::SURFACE_TYPE_IMAGE_READER,
};

inline const std::set<int64_t> VALID_STREAM_USE_CASES = {
        ANDROID_SCALER_AVAILABLE_STREAM_USE_CASES_DEFAULT,
        ANDROID_SCALER_AVAILABLE_STREAM_USE_CASES_PREVIEW,
        ANDROID_SCALER_AVAILABLE_STREAM_USE_CASES_STILL_CAPTURE,
        ANDROID_SCALER_AVAILABLE_STREAM_USE_CASES_VIDEO_RECORD,
        ANDROID_SCALER_AVAILABLE_STREAM_USE_CASES_PREVIEW_VIDEO_STILL,
        ANDROID_SCALER_AVAILABLE_STREAM_USE_CASES_VIDEO_CALL,
        ANDROID_SCALER_AVAILABLE_STREAM_USE_CASES_CROPPED_RAW,
        ANDROID_SCALER_AVAILABLE_STREAM_USE_CASES_VENDOR_START,
};

inline const std::set<int64_t> VALID_TIMESTAMP_BASES = {
        OutputConfiguration::TIMESTAMP_BASE_DEFAULT,
        OutputConfiguration::TIMESTAMP_BASE_SENSOR,
        OutputConfiguration::TIMESTAMP_BASE_MONOTONIC,
        OutputConfiguration::TIMESTAMP_BASE_REALTIME,
        OutputConfiguration::TIMESTAMP_BASE_CHOREOGRAPHER_SYNCED,
        OutputConfiguration::TIMESTAMP_BASE_MAX,
};

inline const std::set<int64_t> VALID_MIRROR_MODES = {
        OutputConfiguration::MIRROR_MODE_AUTO,
        OutputConfiguration::MIRROR_MODE_NONE,
        OutputConfiguration::MIRROR_MODE_H,
        OutputConfiguration::MIRROR_MODE_V,
};

inline const std::set<int64_t> VALID_FORMATS = {
        HAL_PIXEL_FORMAT_RGBA_8888,
        HAL_PIXEL_FORMAT_RGBX_8888,
        HAL_PIXEL_FORMAT_RGB_888,
        HAL_PIXEL_FORMAT_RGB_565,
        HAL_PIXEL_FORMAT_BGRA_8888,
        HAL_PIXEL_FORMAT_YCBCR_422_SP,
        HAL_PIXEL_FORMAT_YCRCB_420_SP,
        HAL_PIXEL_FORMAT_YCBCR_422_I,
        HAL_PIXEL_FORMAT_RGBA_FP16,
        HAL_PIXEL_FORMAT_RAW16,
        HAL_PIXEL_FORMAT_BLOB,
        HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED,
        HAL_PIXEL_FORMAT_YCBCR_420_888,
        HAL_PIXEL_FORMAT_RAW_OPAQUE,
        HAL_PIXEL_FORMAT_RAW10,
        HAL_PIXEL_FORMAT_RAW12,
        static_cast<int64_t>(AidlPixelFormat::RAW14),
        HAL_PIXEL_FORMAT_RGBA_1010102,
        HAL_PIXEL_FORMAT_Y8,
        HAL_PIXEL_FORMAT_Y16,
        HAL_PIXEL_FORMAT_YV12,
        HAL_PIXEL_FORMAT_DEPTH_16,
        HAL_PIXEL_FORMAT_DEPTH_24,
        HAL_PIXEL_FORMAT_DEPTH_24_STENCIL_8,
        HAL_PIXEL_FORMAT_DEPTH_32F,
        HAL_PIXEL_FORMAT_DEPTH_32F_STENCIL_8,
        HAL_PIXEL_FORMAT_STENCIL_8,
        HAL_PIXEL_FORMAT_YCBCR_P010,
        HAL_PIXEL_FORMAT_HSV_888,
};

inline const std::set<int64_t> VALID_USAGES = {
        AHARDWAREBUFFER_USAGE_CPU_READ_NEVER,
        AHARDWAREBUFFER_USAGE_CPU_READ_RARELY,
        AHARDWAREBUFFER_USAGE_CPU_READ_OFTEN,
        AHARDWAREBUFFER_USAGE_CPU_WRITE_NEVER,
        AHARDWAREBUFFER_USAGE_CPU_WRITE_RARELY,
        AHARDWAREBUFFER_USAGE_CPU_WRITE_OFTEN,
        AHARDWAREBUFFER_USAGE_GPU_FRAMEBUFFER,
        AHARDWAREBUFFER_USAGE_GPU_COLOR_OUTPUT,
        AHARDWAREBUFFER_USAGE_COMPOSER_OVERLAY,
        AHARDWAREBUFFER_USAGE_PROTECTED_CONTENT,
        AHARDWAREBUFFER_USAGE_VIDEO_ENCODE,
        AHARDWAREBUFFER_USAGE_SENSOR_DIRECT_DATA,
        AHARDWAREBUFFER_USAGE_GPU_DATA_BUFFER,
        AHARDWAREBUFFER_USAGE_GPU_CUBE_MAP,
        AHARDWAREBUFFER_USAGE_GPU_MIPMAP_COMPLETE,
        AHARDWAREBUFFER_USAGE_FRONT_BUFFER,
        AHARDWAREBUFFER_USAGE_VENDOR_0,
        AHARDWAREBUFFER_USAGE_VENDOR_1,
        AHARDWAREBUFFER_USAGE_VENDOR_2,
        AHARDWAREBUFFER_USAGE_VENDOR_3,
        AHARDWAREBUFFER_USAGE_VENDOR_4,
        AHARDWAREBUFFER_USAGE_VENDOR_5,
        AHARDWAREBUFFER_USAGE_VENDOR_6,
        AHARDWAREBUFFER_USAGE_VENDOR_7,
        AHARDWAREBUFFER_USAGE_VENDOR_8,
        AHARDWAREBUFFER_USAGE_VENDOR_9,
        AHARDWAREBUFFER_USAGE_VENDOR_10,
        AHARDWAREBUFFER_USAGE_VENDOR_11,
        AHARDWAREBUFFER_USAGE_VENDOR_12,
        AHARDWAREBUFFER_USAGE_VENDOR_13,
        AHARDWAREBUFFER_USAGE_VENDOR_14,
        AHARDWAREBUFFER_USAGE_VENDOR_15,
        AHARDWAREBUFFER_USAGE_VENDOR_16,
        AHARDWAREBUFFER_USAGE_VENDOR_17,
        AHARDWAREBUFFER_USAGE_VENDOR_18,
};

inline const std::set<int64_t> VALID_DATA_SPACES = {
        HAL_DATASPACE_UNKNOWN,
        HAL_DATASPACE_ARBITRARY,
        HAL_DATASPACE_STANDARD_UNSPECIFIED,
        HAL_DATASPACE_STANDARD_BT709,
        HAL_DATASPACE_STANDARD_BT601_625,
        HAL_DATASPACE_STANDARD_BT601_625_UNADJUSTED,
        HAL_DATASPACE_STANDARD_BT601_525,
        HAL_DATASPACE_STANDARD_BT601_525_UNADJUSTED,
        HAL_DATASPACE_STANDARD_BT2020,
        HAL_DATASPACE_STANDARD_BT2020_CONSTANT_LUMINANCE,
        HAL_DATASPACE_STANDARD_BT470M,
        HAL_DATASPACE_STANDARD_FILM,
        HAL_DATASPACE_STANDARD_DCI_P3,
        HAL_DATASPACE_STANDARD_ADOBE_RGB,
        HAL_DATASPACE_TRANSFER_UNSPECIFIED,
        HAL_DATASPACE_TRANSFER_LINEAR,
        HAL_DATASPACE_TRANSFER_SRGB,
        HAL_DATASPACE_TRANSFER_SMPTE_170M,
        HAL_DATASPACE_TRANSFER_GAMMA2_2,
        HAL_DATASPACE_TRANSFER_GAMMA2_6,
        HAL_DATASPACE_TRANSFER_GAMMA2_8,
        HAL_DATASPACE_TRANSFER_ST2084,
        HAL_DATASPACE_TRANSFER_HLG,
        HAL_DATASPACE_RANGE_UNSPECIFIED,
        HAL_DATASPACE_RANGE_FULL,
        HAL_DATASPACE_RANGE_LIMITED,
        HAL_DATASPACE_RANGE_EXTENDED,
        HAL_DATASPACE_SRGB_LINEAR,
        HAL_DATASPACE_V0_SRGB_LINEAR,
        HAL_DATASPACE_V0_SCRGB_LINEAR,
        HAL_DATASPACE_SRGB,
        HAL_DATASPACE_V0_SRGB,
        HAL_DATASPACE_V0_SCRGB,
        HAL_DATASPACE_JFIF,
        HAL_DATASPACE_V0_JFIF,
        HAL_DATASPACE_BT601_625,
        HAL_DATASPACE_V0_BT601_625,
        HAL_DATASPACE_BT601_525,
        HAL_DATASPACE_V0_BT601_525,
        HAL_DATASPACE_BT709,
        HAL_DATASPACE_V0_BT709,
        HAL_DATASPACE_DCI_P3_LINEAR,
        HAL_DATASPACE_DCI_P3,
        HAL_DATASPACE_DISPLAY_P3_LINEAR,
        HAL_DATASPACE_DISPLAY_P3,
        HAL_DATASPACE_ADOBE_RGB,
        HAL_DATASPACE_BT2020_LINEAR,
        HAL_DATASPACE_BT2020,
        HAL_DATASPACE_BT2020_PQ,
        HAL_DATASPACE_DEPTH,
        HAL_DATASPACE_SENSOR,
};

class SharedSessionConfigUtils {
public:

    // toString function for ErrorCode enum.
    static const char* toString(ErrorCode errorCode);

    // Convert string representation of colorspace to its int value.
    static ErrorCode getColorSpaceFromStr(const char* colorSpaceStr, int32_t* colorSpace);

    // Convert string representation of surface type to its int value.
    static ErrorCode getSurfaceTypeFromXml(const XMLElement* surfaceTypeXml, int64_t* surfaceType);

    // Convert string representation of width to its int value.
    static ErrorCode getWidthFromXml(const XMLElement* widthXml, int64_t* width);

    // Convert string representation of height to its int value.
    static ErrorCode getHeightFromXml(const XMLElement* heightXml, int64_t* height);

    // Convert string representation of physical cameraId to its std::string value.
    static ErrorCode getPhysicalCameraIdFromXml(const XMLElement* physicalCameraIdXml,
                                                std::string* physicalCameraId);

    // Convert string representation of stream use case to its int64 value.
    static ErrorCode getStreamUseCaseFromXml(const XMLElement* streamUseCaseXml,
                                             int64_t* streamUseCase);

    // Convert string representation of timestamp base to its int value.
    static ErrorCode getTimestampBaseFromXml(const XMLElement* timestampBaseXml,
                                             int64_t* timestampBase);

    // Convert string representation of mirror mode to its int value.
    static ErrorCode getMirrorModeFromXml(const XMLElement* mirrorModeXml, int64_t* mirrorMode);

    // Convert string representation of use readout timestamp to its bool value.
    static ErrorCode getUseReadoutTimestampFromXml(const XMLElement* useReadoutTimestampXml,
                                                   bool* useReadoutTimestamp);

    // Convert string representation of format to its int value.
    static ErrorCode getFormatFromXml(const XMLElement* formatXml, int64_t* format,
                                      int64_t surfaceType);

    // Convert string representation of usage to its int64 value.
    static ErrorCode getUsageFromXml(const XMLElement* usageXml, int64_t* usage,
                                     int64_t surfaceType);

    // Convert string representation of data space to its int value.
    static ErrorCode getDataSpaceFromXml(const XMLElement* dataSpaceXml, int64_t* dataSpace);

    static std::vector<std::string> splitString(std::string inputString, char delimiter);

    static std::string setToString(const std::set<int64_t>& s);
};

}  // namespace android

#endif  // ANDROID_SERVERS_CAMERA_SHAREDSESSIONCONFIGUTILS_H_
