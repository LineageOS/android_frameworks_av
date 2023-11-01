/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include <cutils/properties.h>

#include "SessionConfigurationUtils.h"
#include "../api2/DepthCompositeStream.h"
#include "../api2/HeicCompositeStream.h"
#include "aidl/android/hardware/graphics/common/Dataspace.h"
#include "api2/JpegRCompositeStream.h"
#include "common/CameraDeviceBase.h"
#include "common/HalConversionsTemplated.h"
#include "../CameraService.h"
#include "device3/aidl/AidlCamera3Device.h"
#include "device3/hidl/HidlCamera3Device.h"
#include "device3/Camera3OutputStream.h"
#include "system/graphics-base-v1.1.h"
#include <camera/StringUtils.h>
#include <ui/PublicFormat.h>

using android::camera3::OutputStreamInfo;
using android::camera3::OutputStreamInfo;
using android::hardware::camera2::ICameraDeviceUser;

namespace android {
namespace camera3 {

void StreamConfiguration::getStreamConfigurations(
        const CameraMetadata &staticInfo, int configuration,
        std::unordered_map<int, std::vector<StreamConfiguration>> *scm) {
    if (scm == nullptr) {
        ALOGE("%s: StreamConfigurationMap nullptr", __FUNCTION__);
        return;
    }
    const int STREAM_FORMAT_OFFSET = 0;
    const int STREAM_WIDTH_OFFSET = 1;
    const int STREAM_HEIGHT_OFFSET = 2;
    const int STREAM_IS_INPUT_OFFSET = 3;

    camera_metadata_ro_entry availableStreamConfigs = staticInfo.find(configuration);
    for (size_t i = 0; i < availableStreamConfigs.count; i += 4) {
        int32_t format = availableStreamConfigs.data.i32[i + STREAM_FORMAT_OFFSET];
        int32_t width = availableStreamConfigs.data.i32[i + STREAM_WIDTH_OFFSET];
        int32_t height = availableStreamConfigs.data.i32[i + STREAM_HEIGHT_OFFSET];
        int32_t isInput = availableStreamConfigs.data.i32[i + STREAM_IS_INPUT_OFFSET];
        StreamConfiguration sc = {format, width, height, isInput};
        (*scm)[format].push_back(sc);
    }
}

void StreamConfiguration::getStreamConfigurations(
        const CameraMetadata &staticInfo, bool maxRes,
        std::unordered_map<int, std::vector<StreamConfiguration>> *scm) {
    int32_t scalerKey =
            SessionConfigurationUtils::getAppropriateModeTag(
                    ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS, maxRes);

    int32_t depthKey =
            SessionConfigurationUtils::getAppropriateModeTag(
                    ANDROID_DEPTH_AVAILABLE_DEPTH_STREAM_CONFIGURATIONS, maxRes);

    int32_t dynamicDepthKey =
            SessionConfigurationUtils::getAppropriateModeTag(
                    ANDROID_DEPTH_AVAILABLE_DYNAMIC_DEPTH_STREAM_CONFIGURATIONS, maxRes);

    int32_t heicKey =
            SessionConfigurationUtils::getAppropriateModeTag(
                    ANDROID_HEIC_AVAILABLE_HEIC_STREAM_CONFIGURATIONS, maxRes);

    getStreamConfigurations(staticInfo, scalerKey, scm);
    getStreamConfigurations(staticInfo, depthKey, scm);
    getStreamConfigurations(staticInfo, dynamicDepthKey, scm);
    getStreamConfigurations(staticInfo, heicKey, scm);
}

namespace SessionConfigurationUtils {

int32_t PERF_CLASS_LEVEL =
        property_get_int32("ro.odm.build.media_performance_class", 0);

bool IS_PERF_CLASS = (PERF_CLASS_LEVEL >= SDK_VERSION_S);

camera3::Size getMaxJpegResolution(const CameraMetadata &metadata,
        bool ultraHighResolution) {
    int32_t maxJpegWidth = 0, maxJpegHeight = 0;
    const int STREAM_CONFIGURATION_SIZE = 4;
    const int STREAM_FORMAT_OFFSET = 0;
    const int STREAM_WIDTH_OFFSET = 1;
    const int STREAM_HEIGHT_OFFSET = 2;
    const int STREAM_IS_INPUT_OFFSET = 3;

    int32_t scalerSizesTag = ultraHighResolution ?
            ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS_MAXIMUM_RESOLUTION :
                    ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS;
    camera_metadata_ro_entry_t availableStreamConfigs =
            metadata.find(scalerSizesTag);
    if (availableStreamConfigs.count == 0 ||
            availableStreamConfigs.count % STREAM_CONFIGURATION_SIZE != 0) {
        return camera3::Size(0, 0);
    }

    // Get max jpeg size (area-wise).
    for (size_t i= 0; i < availableStreamConfigs.count; i+= STREAM_CONFIGURATION_SIZE) {
        int32_t format = availableStreamConfigs.data.i32[i + STREAM_FORMAT_OFFSET];
        int32_t width = availableStreamConfigs.data.i32[i + STREAM_WIDTH_OFFSET];
        int32_t height = availableStreamConfigs.data.i32[i + STREAM_HEIGHT_OFFSET];
        int32_t isInput = availableStreamConfigs.data.i32[i + STREAM_IS_INPUT_OFFSET];
        if (isInput == ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS_OUTPUT
                && format == HAL_PIXEL_FORMAT_BLOB &&
                (width * height > maxJpegWidth * maxJpegHeight)) {
            maxJpegWidth = width;
            maxJpegHeight = height;
        }
    }

    return camera3::Size(maxJpegWidth, maxJpegHeight);
}

size_t getUHRMaxJpegBufferSize(camera3::Size uhrMaxJpegSize,
        camera3::Size defaultMaxJpegSize, size_t defaultMaxJpegBufferSize) {
    return ((float)(uhrMaxJpegSize.width * uhrMaxJpegSize.height)) /
            (defaultMaxJpegSize.width * defaultMaxJpegSize.height) * defaultMaxJpegBufferSize;
}

StreamConfigurationPair
getStreamConfigurationPair(const CameraMetadata &staticInfo) {
    camera3::StreamConfigurationPair streamConfigurationPair;
    camera3::StreamConfiguration::getStreamConfigurations(staticInfo, false,
            &streamConfigurationPair.mDefaultStreamConfigurationMap);
    camera3::StreamConfiguration::getStreamConfigurations(staticInfo, true,
            &streamConfigurationPair.mMaximumResolutionStreamConfigurationMap);
    return streamConfigurationPair;
}

int64_t euclidDistSquare(int32_t x0, int32_t y0, int32_t x1, int32_t y1) {
    int64_t d0 = x0 - x1;
    int64_t d1 = y0 - y1;
    return d0 * d0 + d1 * d1;
}

bool roundBufferDimensionNearest(int32_t width, int32_t height,
        int32_t format, android_dataspace dataSpace,
        const CameraMetadata& info, bool maxResolution, /*out*/int32_t* outWidth,
        /*out*/int32_t* outHeight) {
    const int32_t depthSizesTag =
            getAppropriateModeTag(ANDROID_DEPTH_AVAILABLE_DEPTH_STREAM_CONFIGURATIONS,
                    maxResolution);
    const int32_t scalerSizesTag =
            getAppropriateModeTag(ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS, maxResolution);
    const int32_t heicSizesTag =
            getAppropriateModeTag(ANDROID_HEIC_AVAILABLE_HEIC_STREAM_CONFIGURATIONS, maxResolution);
    const int32_t jpegRSizesTag = getAppropriateModeTag(
            ANDROID_JPEGR_AVAILABLE_JPEG_R_STREAM_CONFIGURATIONS, maxResolution);

    bool isJpegRDataSpace = (dataSpace == static_cast<android_dataspace_t>(
                ::aidl::android::hardware::graphics::common::Dataspace::JPEG_R));
    camera_metadata_ro_entry streamConfigs =
            (isJpegRDataSpace) ? info.find(jpegRSizesTag) :
            (dataSpace == HAL_DATASPACE_DEPTH) ? info.find(depthSizesTag) :
            (dataSpace == static_cast<android_dataspace>(HAL_DATASPACE_HEIF)) ?
            info.find(heicSizesTag) :
            info.find(scalerSizesTag);

    int32_t bestWidth = -1;
    int32_t bestHeight = -1;

    // Iterate through listed stream configurations and find the one with the smallest euclidean
    // distance from the given dimensions for the given format.
    for (size_t i = 0; i < streamConfigs.count; i += 4) {
        int32_t fmt = streamConfigs.data.i32[i];
        int32_t w = streamConfigs.data.i32[i + 1];
        int32_t h = streamConfigs.data.i32[i + 2];

        // Ignore input/output type for now
        if (fmt == format) {
            if (w == width && h == height) {
                bestWidth = width;
                bestHeight = height;
                break;
            } else if (w <= ROUNDING_WIDTH_CAP && (bestWidth == -1 ||
                    SessionConfigurationUtils::euclidDistSquare(w, h, width, height) <
                    SessionConfigurationUtils::euclidDistSquare(bestWidth, bestHeight, width,
                            height))) {
                bestWidth = w;
                bestHeight = h;
            }
        }
    }

    if (bestWidth == -1) {
        // Return false if no configurations for this format were listed
        ALOGE("%s: No configurations for format %d width %d, height %d, maxResolution ? %s",
                __FUNCTION__, format, width, height, maxResolution ? "true" : "false");
        return false;
    }

    // Set the outputs to the closet width/height
    if (outWidth != NULL) {
        *outWidth = bestWidth;
    }
    if (outHeight != NULL) {
        *outHeight = bestHeight;
    }

    // Return true if at least one configuration for this format was listed
    return true;
}

//check if format is 10-bit compatible
bool is10bitCompatibleFormat(int32_t format, android_dataspace_t dataSpace) {
    switch(format) {
        case HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED:
        case HAL_PIXEL_FORMAT_YCBCR_P010:
            return true;
        case HAL_PIXEL_FORMAT_BLOB:
            if (dataSpace == static_cast<android_dataspace_t>(
                        ::aidl::android::hardware::graphics::common::Dataspace::JPEG_R)) {
                return true;
            }

            return false;
        default:
            return false;
    }
}

bool isDynamicRangeProfileSupported(int64_t dynamicRangeProfile, const CameraMetadata& staticInfo) {
    if (dynamicRangeProfile == ANDROID_REQUEST_AVAILABLE_DYNAMIC_RANGE_PROFILES_MAP_STANDARD) {
        // Supported by default
        return true;
    }

    camera_metadata_ro_entry_t entry = staticInfo.find(ANDROID_REQUEST_AVAILABLE_CAPABILITIES);
    bool is10bitDynamicRangeSupported = false;
    for (size_t i = 0; i < entry.count; ++i) {
        uint8_t capability = entry.data.u8[i];
        if (capability == ANDROID_REQUEST_AVAILABLE_CAPABILITIES_DYNAMIC_RANGE_TEN_BIT) {
            is10bitDynamicRangeSupported = true;
            break;
        }
    }

    if (!is10bitDynamicRangeSupported) {
        return false;
    }

    switch (dynamicRangeProfile) {
        case ANDROID_REQUEST_AVAILABLE_DYNAMIC_RANGE_PROFILES_MAP_HDR10_PLUS:
        case ANDROID_REQUEST_AVAILABLE_DYNAMIC_RANGE_PROFILES_MAP_HDR10:
        case ANDROID_REQUEST_AVAILABLE_DYNAMIC_RANGE_PROFILES_MAP_HLG10:
        case ANDROID_REQUEST_AVAILABLE_DYNAMIC_RANGE_PROFILES_MAP_DOLBY_VISION_10B_HDR_OEM:
        case ANDROID_REQUEST_AVAILABLE_DYNAMIC_RANGE_PROFILES_MAP_DOLBY_VISION_10B_HDR_OEM_PO:
        case ANDROID_REQUEST_AVAILABLE_DYNAMIC_RANGE_PROFILES_MAP_DOLBY_VISION_10B_HDR_REF:
        case ANDROID_REQUEST_AVAILABLE_DYNAMIC_RANGE_PROFILES_MAP_DOLBY_VISION_10B_HDR_REF_PO:
        case ANDROID_REQUEST_AVAILABLE_DYNAMIC_RANGE_PROFILES_MAP_DOLBY_VISION_8B_HDR_OEM:
        case ANDROID_REQUEST_AVAILABLE_DYNAMIC_RANGE_PROFILES_MAP_DOLBY_VISION_8B_HDR_OEM_PO:
        case ANDROID_REQUEST_AVAILABLE_DYNAMIC_RANGE_PROFILES_MAP_DOLBY_VISION_8B_HDR_REF:
        case ANDROID_REQUEST_AVAILABLE_DYNAMIC_RANGE_PROFILES_MAP_DOLBY_VISION_8B_HDR_REF_PO:
            entry = staticInfo.find(ANDROID_REQUEST_AVAILABLE_DYNAMIC_RANGE_PROFILES_MAP);
            for (size_t i = 0; i < entry.count; i += 3) {
                if (dynamicRangeProfile == entry.data.i64[i]) {
                    return true;
                }
            }

            return false;
        default:
            return false;
    }

    return false;
}

//check if format is 10-bit compatible
bool is10bitDynamicRangeProfile(int64_t dynamicRangeProfile) {
    switch (dynamicRangeProfile) {
        case ANDROID_REQUEST_AVAILABLE_DYNAMIC_RANGE_PROFILES_MAP_HDR10_PLUS:
        case ANDROID_REQUEST_AVAILABLE_DYNAMIC_RANGE_PROFILES_MAP_HDR10:
        case ANDROID_REQUEST_AVAILABLE_DYNAMIC_RANGE_PROFILES_MAP_HLG10:
        case ANDROID_REQUEST_AVAILABLE_DYNAMIC_RANGE_PROFILES_MAP_DOLBY_VISION_10B_HDR_OEM:
        case ANDROID_REQUEST_AVAILABLE_DYNAMIC_RANGE_PROFILES_MAP_DOLBY_VISION_10B_HDR_OEM_PO:
        case ANDROID_REQUEST_AVAILABLE_DYNAMIC_RANGE_PROFILES_MAP_DOLBY_VISION_10B_HDR_REF:
        case ANDROID_REQUEST_AVAILABLE_DYNAMIC_RANGE_PROFILES_MAP_DOLBY_VISION_10B_HDR_REF_PO:
            return true;
        default:
            return false;
    }
}

bool deviceReportsColorSpaces(const CameraMetadata& staticInfo) {
    camera_metadata_ro_entry_t entry = staticInfo.find(ANDROID_REQUEST_AVAILABLE_CAPABILITIES);
    for (size_t i = 0; i < entry.count; ++i) {
        uint8_t capability = entry.data.u8[i];
        if (capability == ANDROID_REQUEST_AVAILABLE_CAPABILITIES_COLOR_SPACE_PROFILES) {
            return true;
        }
    }

    return false;
}

bool isColorSpaceSupported(int32_t colorSpace, int32_t format, android_dataspace dataSpace,
        int64_t dynamicRangeProfile, const CameraMetadata& staticInfo) {
    int64_t colorSpace64 = colorSpace;
    int64_t format64 = format;

    // Translate HAL format + data space to public format
    if (format == HAL_PIXEL_FORMAT_BLOB && dataSpace == HAL_DATASPACE_V0_JFIF) {
        format64 = 0x100; // JPEG
    } else if (format == HAL_PIXEL_FORMAT_BLOB
            && dataSpace == static_cast<android_dataspace>(HAL_DATASPACE_HEIF)) {
        format64 = 0x48454946; // HEIC
    } else if (format == HAL_PIXEL_FORMAT_BLOB
            && dataSpace == static_cast<android_dataspace>(HAL_DATASPACE_DYNAMIC_DEPTH)) {
        format64 = 0x69656963; // DEPTH_JPEG
    } else if (format == HAL_PIXEL_FORMAT_BLOB && dataSpace == HAL_DATASPACE_DEPTH) {
        return false; // DEPTH_POINT_CLOUD, not applicable
    } else if (format == HAL_PIXEL_FORMAT_Y16 && dataSpace == HAL_DATASPACE_DEPTH) {
        return false; // DEPTH16, not applicable
    } else if (format == HAL_PIXEL_FORMAT_RAW16 && dataSpace == HAL_DATASPACE_DEPTH) {
        return false; // RAW_DEPTH, not applicable
    } else if (format == HAL_PIXEL_FORMAT_RAW10 && dataSpace == HAL_DATASPACE_DEPTH) {
        return false; // RAW_DEPTH10, not applicable
    } else if (format == HAL_PIXEL_FORMAT_BLOB && dataSpace ==
            static_cast<android_dataspace>(
                ::aidl::android::hardware::graphics::common::Dataspace::JPEG_R)) {
        format64 = static_cast<int64_t>(PublicFormat::JPEG_R);
    }

    camera_metadata_ro_entry_t entry =
            staticInfo.find(ANDROID_REQUEST_AVAILABLE_COLOR_SPACE_PROFILES_MAP);
    for (size_t i = 0; i < entry.count; i += 3) {
        bool isFormatCompatible = (format64 == entry.data.i64[i + 1]);
        bool isDynamicProfileCompatible =
                (dynamicRangeProfile & entry.data.i64[i + 2]) != 0;

        if (colorSpace64 == entry.data.i64[i]
                && isFormatCompatible
                && isDynamicProfileCompatible) {
            return true;
        }
    }

    ALOGE("Color space %d, image format %" PRId64 ", and dynamic range 0x%" PRIx64
            " combination not found", colorSpace, format64, dynamicRangeProfile);
    return false;
}

bool isPublicFormat(int32_t format)
{
    switch(format) {
        case HAL_PIXEL_FORMAT_RGBA_8888:
        case HAL_PIXEL_FORMAT_RGBX_8888:
        case HAL_PIXEL_FORMAT_RGB_888:
        case HAL_PIXEL_FORMAT_RGB_565:
        case HAL_PIXEL_FORMAT_BGRA_8888:
        case HAL_PIXEL_FORMAT_YV12:
        case HAL_PIXEL_FORMAT_Y8:
        case HAL_PIXEL_FORMAT_Y16:
        case HAL_PIXEL_FORMAT_RAW16:
        case HAL_PIXEL_FORMAT_RAW10:
        case HAL_PIXEL_FORMAT_RAW12:
        case HAL_PIXEL_FORMAT_RAW_OPAQUE:
        case HAL_PIXEL_FORMAT_BLOB:
        case HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED:
        case HAL_PIXEL_FORMAT_YCbCr_420_888:
        case HAL_PIXEL_FORMAT_YCbCr_422_SP:
        case HAL_PIXEL_FORMAT_YCrCb_420_SP:
        case HAL_PIXEL_FORMAT_YCbCr_422_I:
            return true;
        default:
            return false;
    }
}

bool dataSpaceFromColorSpace(android_dataspace *dataSpace, int32_t colorSpace) {
    switch (colorSpace) {
        case ANDROID_REQUEST_AVAILABLE_COLOR_SPACE_PROFILES_MAP_SRGB:
            *dataSpace = HAL_DATASPACE_V0_SRGB;
            return true;
        case ANDROID_REQUEST_AVAILABLE_COLOR_SPACE_PROFILES_MAP_DISPLAY_P3:
            *dataSpace = HAL_DATASPACE_DISPLAY_P3;
            return true;
        case ANDROID_REQUEST_AVAILABLE_COLOR_SPACE_PROFILES_MAP_BT2020_HLG:
            *(reinterpret_cast<int32_t*>(dataSpace)) = HAL_DATASPACE_BT2020_HLG;
            return true;
        default:
            ALOGE("%s: Unsupported color space %d", __FUNCTION__, colorSpace);
            return false;
    }
}

bool isStreamUseCaseSupported(int64_t streamUseCase,
        const CameraMetadata &deviceInfo) {
    camera_metadata_ro_entry_t availableStreamUseCases =
            deviceInfo.find(ANDROID_SCALER_AVAILABLE_STREAM_USE_CASES);

    if (availableStreamUseCases.count == 0 &&
            streamUseCase == ANDROID_SCALER_AVAILABLE_STREAM_USE_CASES_DEFAULT) {
        return true;
    }
    // Allow vendor stream use case unconditionally.
    if (streamUseCase >= ANDROID_SCALER_AVAILABLE_STREAM_USE_CASES_VENDOR_START) {
        return true;
    }

    for (size_t i = 0; i < availableStreamUseCases.count; i++) {
        if (availableStreamUseCases.data.i64[i] == streamUseCase) {
            return true;
        }
    }
    return false;
}

binder::Status createSurfaceFromGbp(
        OutputStreamInfo& streamInfo, bool isStreamInfoValid,
        sp<Surface>& surface, const sp<IGraphicBufferProducer>& gbp,
        const std::string &logicalCameraId, const CameraMetadata &physicalCameraMetadata,
        const std::vector<int32_t> &sensorPixelModesUsed, int64_t dynamicRangeProfile,
        int64_t streamUseCase, int timestampBase, int mirrorMode,
        int32_t colorSpace) {
    // bufferProducer must be non-null
    if (gbp == nullptr) {
        std::string msg = fmt::sprintf("Camera %s: Surface is NULL", logicalCameraId.c_str());
        ALOGW("%s: %s", __FUNCTION__, msg.c_str());
        return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT, msg.c_str());
    }
    // HACK b/10949105
    // Query consumer usage bits to set async operation mode for
    // GLConsumer using controlledByApp parameter.
    bool useAsync = false;
    uint64_t consumerUsage = 0;
    status_t err;
    if ((err = gbp->getConsumerUsage(&consumerUsage)) != OK) {
        std::string msg = fmt::sprintf("Camera %s: Failed to query Surface consumer usage: %s (%d)",
                logicalCameraId.c_str(), strerror(-err), err);
        ALOGE("%s: %s", __FUNCTION__, msg.c_str());
        return STATUS_ERROR(CameraService::ERROR_INVALID_OPERATION, msg.c_str());
    }
    if (consumerUsage & GraphicBuffer::USAGE_HW_TEXTURE) {
        ALOGW("%s: Camera %s with consumer usage flag: %" PRIu64 ": Forcing asynchronous mode for"
                "stream", __FUNCTION__, logicalCameraId.c_str(), consumerUsage);
        useAsync = true;
    }

    uint64_t disallowedFlags = GraphicBuffer::USAGE_HW_VIDEO_ENCODER |
                              GRALLOC_USAGE_RENDERSCRIPT;
    uint64_t allowedFlags = GraphicBuffer::USAGE_SW_READ_MASK |
                           GraphicBuffer::USAGE_HW_TEXTURE |
                           GraphicBuffer::USAGE_HW_COMPOSER;
    bool flexibleConsumer = (consumerUsage & disallowedFlags) == 0 &&
            (consumerUsage & allowedFlags) != 0;

    surface = new Surface(gbp, useAsync);
    ANativeWindow *anw = surface.get();

    int width, height, format;
    android_dataspace dataSpace;
    if ((err = anw->query(anw, NATIVE_WINDOW_WIDTH, &width)) != OK) {
        std::string msg = fmt::sprintf("Camera %s: Failed to query Surface width: %s (%d)",
                 logicalCameraId.c_str(), strerror(-err), err);
        ALOGE("%s: %s", __FUNCTION__, msg.c_str());
        return STATUS_ERROR(CameraService::ERROR_INVALID_OPERATION, msg.c_str());
    }
    if ((err = anw->query(anw, NATIVE_WINDOW_HEIGHT, &height)) != OK) {
        std::string msg = fmt::sprintf("Camera %s: Failed to query Surface height: %s (%d)",
                logicalCameraId.c_str(), strerror(-err), err);
        ALOGE("%s: %s", __FUNCTION__, msg.c_str());
        return STATUS_ERROR(CameraService::ERROR_INVALID_OPERATION, msg.c_str());
    }
    if ((err = anw->query(anw, NATIVE_WINDOW_FORMAT, &format)) != OK) {
        std::string msg = fmt::sprintf("Camera %s: Failed to query Surface format: %s (%d)",
                logicalCameraId.c_str(), strerror(-err), err);
        ALOGE("%s: %s", __FUNCTION__, msg.c_str());
        return STATUS_ERROR(CameraService::ERROR_INVALID_OPERATION, msg.c_str());
    }
    if ((err = anw->query(anw, NATIVE_WINDOW_DEFAULT_DATASPACE,
            reinterpret_cast<int*>(&dataSpace))) != OK) {
        std::string msg = fmt::sprintf("Camera %s: Failed to query Surface dataspace: %s (%d)",
                logicalCameraId.c_str(), strerror(-err), err);
        ALOGE("%s: %s", __FUNCTION__, msg.c_str());
        return STATUS_ERROR(CameraService::ERROR_INVALID_OPERATION, msg.c_str());
    }

    if (colorSpace != ANDROID_REQUEST_AVAILABLE_COLOR_SPACE_PROFILES_MAP_UNSPECIFIED &&
            format != HAL_PIXEL_FORMAT_BLOB) {
        if (!dataSpaceFromColorSpace(&dataSpace, colorSpace)) {
            std::string msg = fmt::sprintf("Camera %s: color space %d not supported, failed to "
                    "convert to data space", logicalCameraId.c_str(), colorSpace);
            ALOGE("%s: %s", __FUNCTION__, msg.c_str());
            return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT, msg.c_str());
        }
    }

    // FIXME: remove this override since the default format should be
    //       IMPLEMENTATION_DEFINED. b/9487482 & b/35317944
    if ((format >= HAL_PIXEL_FORMAT_RGBA_8888 && format <= HAL_PIXEL_FORMAT_BGRA_8888) &&
            ((consumerUsage & GRALLOC_USAGE_HW_MASK) &&
             ((consumerUsage & GRALLOC_USAGE_SW_READ_MASK) == 0))) {
        ALOGW("%s: Camera %s: Overriding format %#x to IMPLEMENTATION_DEFINED",
                __FUNCTION__, logicalCameraId.c_str(), format);
        format = HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED;
    }
    std::unordered_set<int32_t> overriddenSensorPixelModes;
    if (checkAndOverrideSensorPixelModesUsed(sensorPixelModesUsed, format, width, height,
            physicalCameraMetadata, &overriddenSensorPixelModes) != OK) {
        std::string msg = fmt::sprintf("Camera %s: sensor pixel modes for stream with "
                "format %#x are not valid",logicalCameraId.c_str(), format);
        ALOGE("%s: %s", __FUNCTION__, msg.c_str());
        return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT, msg.c_str());
    }
    bool foundInMaxRes = false;
    if (overriddenSensorPixelModes.find(ANDROID_SENSOR_PIXEL_MODE_MAXIMUM_RESOLUTION) !=
            overriddenSensorPixelModes.end()) {
        // we can use the default stream configuration map
        foundInMaxRes = true;
    }
    // Round dimensions to the nearest dimensions available for this format
    if (flexibleConsumer && isPublicFormat(format) &&
            !SessionConfigurationUtils::roundBufferDimensionNearest(width, height,
            format, dataSpace, physicalCameraMetadata, foundInMaxRes, /*out*/&width,
            /*out*/&height)) {
        std::string msg = fmt::sprintf("Camera %s: No supported stream configurations with "
                "format %#x defined, failed to create output stream",
                logicalCameraId.c_str(), format);
        ALOGE("%s: %s", __FUNCTION__, msg.c_str());
        return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT, msg.c_str());
    }
    if (!SessionConfigurationUtils::isDynamicRangeProfileSupported(dynamicRangeProfile,
                physicalCameraMetadata)) {
        std::string msg = fmt::sprintf("Camera %s: Dynamic range profile 0x%" PRIx64
                " not supported,failed to create output stream", logicalCameraId.c_str(),
                dynamicRangeProfile);
        ALOGE("%s: %s", __FUNCTION__, msg.c_str());
        return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT, msg.c_str());
    }
    if (SessionConfigurationUtils::is10bitDynamicRangeProfile(dynamicRangeProfile) &&
            !SessionConfigurationUtils::is10bitCompatibleFormat(format, dataSpace)) {
        std::string msg = fmt::sprintf("Camera %s: No 10-bit supported stream configurations with "
                "format %#x defined and profile %" PRIx64 ", failed to create output stream",
                logicalCameraId.c_str(), format, dynamicRangeProfile);
        ALOGE("%s: %s", __FUNCTION__, msg.c_str());
        return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT, msg.c_str());
    }
    if (colorSpace != ANDROID_REQUEST_AVAILABLE_COLOR_SPACE_PROFILES_MAP_UNSPECIFIED &&
            SessionConfigurationUtils::deviceReportsColorSpaces(physicalCameraMetadata) &&
            !SessionConfigurationUtils::isColorSpaceSupported(colorSpace, format, dataSpace,
                    dynamicRangeProfile, physicalCameraMetadata)) {
        std::string msg = fmt::sprintf("Camera %s: Color space %d not supported, failed to "
                "create output stream (pixel format %d dynamic range profile %" PRId64 ")",
                logicalCameraId.c_str(), colorSpace, format, dynamicRangeProfile);
        ALOGE("%s: %s", __FUNCTION__, msg.c_str());
        return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT, msg.c_str());
    }
    if (!SessionConfigurationUtils::isStreamUseCaseSupported(streamUseCase,
            physicalCameraMetadata)) {
        std::string msg = fmt::sprintf("Camera %s: stream use case %" PRId64 " not supported,"
                " failed to create output stream", logicalCameraId.c_str(), streamUseCase);
        ALOGE("%s: %s", __FUNCTION__, msg.c_str());
        return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT, msg.c_str());
    }
    if (timestampBase < OutputConfiguration::TIMESTAMP_BASE_DEFAULT ||
            timestampBase > OutputConfiguration::TIMESTAMP_BASE_MAX) {
        std::string msg = fmt::sprintf("Camera %s: invalid timestamp base %d",
                logicalCameraId.c_str(), timestampBase);
        ALOGE("%s: %s", __FUNCTION__, msg.c_str());
        return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT, msg.c_str());
    }
    if (mirrorMode < OutputConfiguration::MIRROR_MODE_AUTO ||
            mirrorMode > OutputConfiguration::MIRROR_MODE_V) {
        std::string msg = fmt::sprintf("Camera %s: invalid mirroring mode %d",
                logicalCameraId.c_str(), mirrorMode);
        ALOGE("%s: %s", __FUNCTION__, msg.c_str());
        return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT, msg.c_str());
    }

    if (!isStreamInfoValid) {
        streamInfo.width = width;
        streamInfo.height = height;
        streamInfo.format = format;
        streamInfo.dataSpace = dataSpace;
        streamInfo.consumerUsage = consumerUsage;
        streamInfo.sensorPixelModesUsed = overriddenSensorPixelModes;
        streamInfo.dynamicRangeProfile = dynamicRangeProfile;
        streamInfo.streamUseCase = streamUseCase;
        streamInfo.timestampBase = timestampBase;
        streamInfo.mirrorMode = mirrorMode;
        streamInfo.colorSpace = colorSpace;
        return binder::Status::ok();
    }
    if (width != streamInfo.width) {
        std::string msg = fmt::sprintf("Camera %s:Surface width doesn't match: %d vs %d",
                logicalCameraId.c_str(), width, streamInfo.width);
        ALOGE("%s: %s", __FUNCTION__, msg.c_str());
        return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT, msg.c_str());
    }
    if (height != streamInfo.height) {
        std::string msg = fmt::sprintf("Camera %s:Surface height doesn't match: %d vs %d",
                 logicalCameraId.c_str(), height, streamInfo.height);
        ALOGE("%s: %s", __FUNCTION__, msg.c_str());
        return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT, msg.c_str());
    }
    if (format != streamInfo.format) {
        std::string msg = fmt::sprintf("Camera %s:Surface format doesn't match: %d vs %d",
                 logicalCameraId.c_str(), format, streamInfo.format);
        ALOGE("%s: %s", __FUNCTION__, msg.c_str());
        return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT, msg.c_str());
    }
    if (format != HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED) {
        if (dataSpace != streamInfo.dataSpace) {
            std::string msg = fmt::sprintf("Camera %s:Surface dataSpace doesn't match: %d vs %d",
                    logicalCameraId.c_str(), static_cast<int>(dataSpace), static_cast<int>(streamInfo.dataSpace));
            ALOGE("%s: %s", __FUNCTION__, msg.c_str());
            return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT, msg.c_str());
        }
        //At the native side, there isn't a way to check whether 2 surfaces come from the same
        //surface class type. Use usage flag to approximate the comparison.
        if (consumerUsage != streamInfo.consumerUsage) {
            std::string msg = fmt::sprintf(
                    "Camera %s:Surface usage flag doesn't match %" PRIu64 " vs %" PRIu64 "",
                    logicalCameraId.c_str(), consumerUsage, streamInfo.consumerUsage);
            ALOGE("%s: %s", __FUNCTION__, msg.c_str());
            return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT, msg.c_str());
        }
    }
    return binder::Status::ok();
}

void mapStreamInfo(const OutputStreamInfo &streamInfo,
            camera3::camera_stream_rotation_t rotation, const std::string &physicalId,
            int32_t groupId, aidl::android::hardware::camera::device::Stream *stream /*out*/) {
    if (stream == nullptr) {
        return;
    }

    stream->streamType = aidl::android::hardware::camera::device::StreamType::OUTPUT;
    stream->width = streamInfo.width;
    stream->height = streamInfo.height;
    stream->format = AidlCamera3Device::mapToAidlPixelFormat(streamInfo.format);
    auto u = streamInfo.consumerUsage;
    camera3::Camera3OutputStream::applyZSLUsageQuirk(streamInfo.format, &u);
    stream->usage = AidlCamera3Device::mapToAidlConsumerUsage(u);
    stream->dataSpace = AidlCamera3Device::mapToAidlDataspace(streamInfo.dataSpace);
    stream->colorSpace = streamInfo.colorSpace;
    stream->rotation = AidlCamera3Device::mapToAidlStreamRotation(rotation);
    stream->id = -1; // Invalid stream id
    stream->physicalCameraId = physicalId;
    stream->bufferSize = 0;
    stream->groupId = groupId;
    stream->sensorPixelModesUsed.resize(streamInfo.sensorPixelModesUsed.size());
    size_t idx = 0;
    using SensorPixelMode = aidl::android::hardware::camera::metadata::SensorPixelMode;
    for (auto mode : streamInfo.sensorPixelModesUsed) {
        stream->sensorPixelModesUsed[idx++] =
                static_cast<SensorPixelMode>(mode);
    }
    using DynamicRangeProfile =
            aidl::android::hardware::camera::metadata::RequestAvailableDynamicRangeProfilesMap;
    stream->dynamicRangeProfile = static_cast<DynamicRangeProfile>(streamInfo.dynamicRangeProfile);
    using StreamUseCases =
            aidl::android::hardware::camera::metadata::ScalerAvailableStreamUseCases;
    stream->useCase = static_cast<StreamUseCases>(streamInfo.streamUseCase);
}

binder::Status
convertToHALStreamCombination(
        const SessionConfiguration& sessionConfiguration,
        const std::string &logicalCameraId, const CameraMetadata &deviceInfo,
        bool isCompositeJpegRDisabled,
        metadataGetter getMetadata, const std::vector<std::string> &physicalCameraIds,
        aidl::android::hardware::camera::device::StreamConfiguration &streamConfiguration,
        bool overrideForPerfClass, bool *earlyExit) {
    using SensorPixelMode = aidl::android::hardware::camera::metadata::SensorPixelMode;
    auto operatingMode = sessionConfiguration.getOperatingMode();
    binder::Status res = checkOperatingMode(operatingMode, deviceInfo,
            logicalCameraId);
    if (!res.isOk()) {
        return res;
    }

    if (earlyExit == nullptr) {
        std::string msg("earlyExit nullptr");
        ALOGE("%s: %s", __FUNCTION__, msg.c_str());
        return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT, msg.c_str());
    }
    *earlyExit = false;
    auto ret = AidlCamera3Device::mapToAidlStreamConfigurationMode(
            static_cast<camera_stream_configuration_mode_t> (operatingMode),
            /*out*/ &streamConfiguration.operationMode);
    if (ret != OK) {
        std::string msg = fmt::sprintf(
            "Camera %s: Failed mapping operating mode %d requested: %s (%d)",
            logicalCameraId.c_str(), operatingMode, strerror(-ret), ret);
        ALOGE("%s: %s", __FUNCTION__, msg.c_str());
        return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT,
                msg.c_str());
    }

    bool isInputValid = (sessionConfiguration.getInputWidth() > 0) &&
            (sessionConfiguration.getInputHeight() > 0) &&
            (sessionConfiguration.getInputFormat() > 0);
    auto outputConfigs = sessionConfiguration.getOutputConfigurations();
    size_t streamCount = outputConfigs.size();
    streamCount = isInputValid ? streamCount + 1 : streamCount;
    streamConfiguration.streams.resize(streamCount);
    size_t streamIdx = 0;
    if (isInputValid) {
        std::vector<SensorPixelMode> defaultSensorPixelModes;
        defaultSensorPixelModes.resize(1);
        defaultSensorPixelModes[0] =
                static_cast<SensorPixelMode>(ANDROID_SENSOR_PIXEL_MODE_DEFAULT);
        aidl::android::hardware::camera::device::Stream stream;
        stream.id = 0;
        stream.streamType =  aidl::android::hardware::camera::device::StreamType::INPUT;
        stream.width = static_cast<uint32_t> (sessionConfiguration.getInputWidth());
        stream.height =  static_cast<uint32_t> (sessionConfiguration.getInputHeight());
        stream.format =
                AidlCamera3Device::AidlCamera3Device::mapToAidlPixelFormat(
                        sessionConfiguration.getInputFormat());
        stream.usage = static_cast<aidl::android::hardware::graphics::common::BufferUsage>(0);
        stream.dataSpace =
              static_cast<aidl::android::hardware::graphics::common::Dataspace>(
                      HAL_DATASPACE_UNKNOWN);
        stream.rotation = aidl::android::hardware::camera::device::StreamRotation::ROTATION_0;
        stream.bufferSize = 0;
        stream.groupId = -1;
        stream.sensorPixelModesUsed = defaultSensorPixelModes;
        using DynamicRangeProfile =
            aidl::android::hardware::camera::metadata::RequestAvailableDynamicRangeProfilesMap;
        stream.dynamicRangeProfile =
            DynamicRangeProfile::ANDROID_REQUEST_AVAILABLE_DYNAMIC_RANGE_PROFILES_MAP_STANDARD;
        streamConfiguration.streams[streamIdx++] = stream;
        streamConfiguration.multiResolutionInputImage =
                sessionConfiguration.inputIsMultiResolution();
    }

    for (const auto &it : outputConfigs) {
        const std::vector<sp<IGraphicBufferProducer>>& bufferProducers =
            it.getGraphicBufferProducers();
        bool deferredConsumer = it.isDeferred();
        const std::string &physicalCameraId = it.getPhysicalCameraId();

        int64_t dynamicRangeProfile = it.getDynamicRangeProfile();
        int32_t colorSpace = it.getColorSpace();
        std::vector<int32_t> sensorPixelModesUsed = it.getSensorPixelModesUsed();
        const CameraMetadata &physicalDeviceInfo = getMetadata(physicalCameraId,
                overrideForPerfClass);
        const CameraMetadata &metadataChosen =
                physicalCameraId.size() > 0 ? physicalDeviceInfo : deviceInfo;

        size_t numBufferProducers = bufferProducers.size();
        bool isStreamInfoValid = false;
        int32_t groupId = it.isMultiResolution() ? it.getSurfaceSetID() : -1;
        OutputStreamInfo streamInfo;

        res = checkSurfaceType(numBufferProducers, deferredConsumer, it.getSurfaceType());
        if (!res.isOk()) {
            return res;
        }
        res = checkPhysicalCameraId(physicalCameraIds, physicalCameraId,
                logicalCameraId);
        if (!res.isOk()) {
            return res;
        }

        int64_t streamUseCase = it.getStreamUseCase();
        int timestampBase = it.getTimestampBase();
        int mirrorMode = it.getMirrorMode();
        if (deferredConsumer) {
            streamInfo.width = it.getWidth();
            streamInfo.height = it.getHeight();
            streamInfo.format = HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED;
            streamInfo.dataSpace = android_dataspace_t::HAL_DATASPACE_UNKNOWN;
            auto surfaceType = it.getSurfaceType();
            streamInfo.consumerUsage = GraphicBuffer::USAGE_HW_TEXTURE;
            if (surfaceType == OutputConfiguration::SURFACE_TYPE_SURFACE_VIEW) {
                streamInfo.consumerUsage |= GraphicBuffer::USAGE_HW_COMPOSER;
            }
            streamInfo.dynamicRangeProfile = it.getDynamicRangeProfile();
            if (checkAndOverrideSensorPixelModesUsed(sensorPixelModesUsed,
                    streamInfo.format, streamInfo.width,
                    streamInfo.height, metadataChosen,
                    &streamInfo.sensorPixelModesUsed) != OK) {
                        ALOGE("%s: Deferred surface sensor pixel modes not valid",
                                __FUNCTION__);
                        return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT,
                                "Deferred surface sensor pixel modes not valid");
            }
            streamInfo.streamUseCase = streamUseCase;
            mapStreamInfo(streamInfo, camera3::CAMERA_STREAM_ROTATION_0, physicalCameraId, groupId,
                    &streamConfiguration.streams[streamIdx++]);
            isStreamInfoValid = true;

            if (numBufferProducers == 0) {
                continue;
            }
        }

        for (auto& bufferProducer : bufferProducers) {
            sp<Surface> surface;
            res = createSurfaceFromGbp(streamInfo, isStreamInfoValid, surface, bufferProducer,
                    logicalCameraId, metadataChosen, sensorPixelModesUsed, dynamicRangeProfile,
                    streamUseCase, timestampBase, mirrorMode, colorSpace);

            if (!res.isOk())
                return res;

            if (!isStreamInfoValid) {
                bool isDepthCompositeStream =
                        camera3::DepthCompositeStream::isDepthCompositeStream(surface);
                bool isHeicCompositeStream =
                        camera3::HeicCompositeStream::isHeicCompositeStream(surface);
                bool isJpegRCompositeStream =
                        camera3::JpegRCompositeStream::isJpegRCompositeStream(surface) &&
                        !isCompositeJpegRDisabled;
                if (isDepthCompositeStream || isHeicCompositeStream || isJpegRCompositeStream) {
                    // We need to take in to account that composite streams can have
                    // additional internal camera streams.
                    std::vector<OutputStreamInfo> compositeStreams;
                    if (isDepthCompositeStream) {
                      // TODO: Take care of composite streams.
                        ret = camera3::DepthCompositeStream::getCompositeStreamInfo(streamInfo,
                                deviceInfo, &compositeStreams);
                    } else if (isHeicCompositeStream) {
                        ret = camera3::HeicCompositeStream::getCompositeStreamInfo(streamInfo,
                            deviceInfo, &compositeStreams);
                    } else {
                        ret = camera3::JpegRCompositeStream::getCompositeStreamInfo(streamInfo,
                            deviceInfo, &compositeStreams);
                    }

                    if (ret != OK) {
                        std::string msg = fmt::sprintf(
                                "Camera %s: Failed adding composite streams: %s (%d)",
                                logicalCameraId.c_str(), strerror(-ret), ret);
                        ALOGE("%s: %s", __FUNCTION__, msg.c_str());
                        return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT, msg.c_str());
                    }

                    if (compositeStreams.size() == 0) {
                        // No internal streams means composite stream not
                        // supported.
                        *earlyExit = true;
                        return binder::Status::ok();
                    } else if (compositeStreams.size() > 1) {
                        streamCount += compositeStreams.size() - 1;
                        streamConfiguration.streams.resize(streamCount);
                    }

                    for (const auto& compositeStream : compositeStreams) {
                        mapStreamInfo(compositeStream,
                                static_cast<camera_stream_rotation_t> (it.getRotation()),
                                physicalCameraId, groupId,
                                &streamConfiguration.streams[streamIdx++]);
                    }
                } else {
                    mapStreamInfo(streamInfo,
                            static_cast<camera_stream_rotation_t> (it.getRotation()),
                            physicalCameraId, groupId, &streamConfiguration.streams[streamIdx++]);
                }
                isStreamInfoValid = true;
            }
        }
    }
    return binder::Status::ok();
}

binder::Status checkPhysicalCameraId(
        const std::vector<std::string> &physicalCameraIds, const std::string &physicalCameraId,
        const std::string &logicalCameraId) {
    if (physicalCameraId.size() == 0) {
        return binder::Status::ok();
    }
    if (std::find(physicalCameraIds.begin(), physicalCameraIds.end(),
        physicalCameraId) == physicalCameraIds.end()) {
        std::string msg = fmt::sprintf("Camera %s: Camera doesn't support physicalCameraId %s.",
                logicalCameraId.c_str(), physicalCameraId.c_str());
        ALOGE("%s: %s", __FUNCTION__, msg.c_str());
        return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT, msg.c_str());
    }
    return binder::Status::ok();
}

binder::Status checkSurfaceType(size_t numBufferProducers,
        bool deferredConsumer, int surfaceType)  {
    if (numBufferProducers > MAX_SURFACES_PER_STREAM) {
        ALOGE("%s: GraphicBufferProducer count %zu for stream exceeds limit of %d",
                __FUNCTION__, numBufferProducers, MAX_SURFACES_PER_STREAM);
        return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT, "Surface count is too high");
    } else if ((numBufferProducers == 0) && (!deferredConsumer)) {
        ALOGE("%s: Number of consumers cannot be smaller than 1", __FUNCTION__);
        return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT, "No valid consumers.");
    }

    bool validSurfaceType = ((surfaceType == OutputConfiguration::SURFACE_TYPE_SURFACE_VIEW) ||
            (surfaceType == OutputConfiguration::SURFACE_TYPE_SURFACE_TEXTURE));

    if (deferredConsumer && !validSurfaceType) {
        ALOGE("%s: Target surface has invalid surfaceType = %d.", __FUNCTION__, surfaceType);
        return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT, "Target Surface is invalid");
    }

    return binder::Status::ok();
}

binder::Status checkOperatingMode(int operatingMode,
        const CameraMetadata &staticInfo, const std::string &cameraId) {
    if (operatingMode < 0) {
        std::string msg = fmt::sprintf(
            "Camera %s: Invalid operating mode %d requested", cameraId.c_str(), operatingMode);
        ALOGE("%s: %s", __FUNCTION__, msg.c_str());
        return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT,
                msg.c_str());
    }

    bool isConstrainedHighSpeed = (operatingMode == ICameraDeviceUser::CONSTRAINED_HIGH_SPEED_MODE);
    if (isConstrainedHighSpeed) {
        camera_metadata_ro_entry_t entry = staticInfo.find(ANDROID_REQUEST_AVAILABLE_CAPABILITIES);
        bool isConstrainedHighSpeedSupported = false;
        for(size_t i = 0; i < entry.count; ++i) {
            uint8_t capability = entry.data.u8[i];
            if (capability == ANDROID_REQUEST_AVAILABLE_CAPABILITIES_CONSTRAINED_HIGH_SPEED_VIDEO) {
                isConstrainedHighSpeedSupported = true;
                break;
            }
        }
        if (!isConstrainedHighSpeedSupported) {
            std::string msg = fmt::sprintf(
                "Camera %s: Try to create a constrained high speed configuration on a device"
                " that doesn't support it.", cameraId.c_str());
            ALOGE("%s: %s", __FUNCTION__, msg.c_str());
            return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT,
                    msg.c_str());
        }
    }

    return binder::Status::ok();
}

static bool inStreamConfigurationMap(int format, int width, int height,
        const std::unordered_map<int, std::vector<camera3::StreamConfiguration>> &sm) {
    auto scs = sm.find(format);
    if (scs == sm.end()) {
        return false;
    }
    for (auto &sc : scs->second) {
        if (sc.width == width && sc.height == height && sc.isInput == 0) {
            return true;
        }
    }
    return false;
}

static std::unordered_set<int32_t> convertToSet(const std::vector<int32_t> &sensorPixelModesUsed) {
    return std::unordered_set<int32_t>(sensorPixelModesUsed.begin(), sensorPixelModesUsed.end());
}

status_t checkAndOverrideSensorPixelModesUsed(
        const std::vector<int32_t> &sensorPixelModesUsed, int format, int width, int height,
        const CameraMetadata &staticInfo,
        std::unordered_set<int32_t> *overriddenSensorPixelModesUsed) {

    const std::unordered_set<int32_t> &sensorPixelModesUsedSet =
            convertToSet(sensorPixelModesUsed);
    if (!supportsUltraHighResolutionCapture(staticInfo)) {
        if (sensorPixelModesUsedSet.find(ANDROID_SENSOR_PIXEL_MODE_MAXIMUM_RESOLUTION) !=
                sensorPixelModesUsedSet.end()) {
            // invalid value for non ultra high res sensors
            ALOGE("%s ANDROID_SENSOR_PIXEL_MODE_MAXIMUM_RESOLUTION used on a device which doesn't "
                    "support ultra high resolution capture", __FUNCTION__);
            return BAD_VALUE;
        }
        overriddenSensorPixelModesUsed->clear();
        overriddenSensorPixelModesUsed->insert(ANDROID_SENSOR_PIXEL_MODE_DEFAULT);
        return OK;
    }

    StreamConfigurationPair streamConfigurationPair = getStreamConfigurationPair(staticInfo);

    bool isInDefaultStreamConfigurationMap =
            inStreamConfigurationMap(format, width, height,
                    streamConfigurationPair.mDefaultStreamConfigurationMap);

    bool isInMaximumResolutionStreamConfigurationMap =
            inStreamConfigurationMap(format, width, height,
                    streamConfigurationPair.mMaximumResolutionStreamConfigurationMap);

    // Case 1: The client has not changed the sensor mode defaults. In this case, we check if the
    // size + format of the OutputConfiguration is found exclusively in 1.
    // If yes, add that sensorPixelMode to overriddenSensorPixelModes.
    // If no, add 'DEFAULT' and MAXIMUM_RESOLUTION to overriddenSensorPixelModes.
    // This maintains backwards compatibility and also tells the framework the stream
    // might be used in either sensor pixel mode.
    if (sensorPixelModesUsedSet.size() == 0) {
        // Ambiguous case, override to include both cases.
        if (isInDefaultStreamConfigurationMap && isInMaximumResolutionStreamConfigurationMap) {
            overriddenSensorPixelModesUsed->insert(ANDROID_SENSOR_PIXEL_MODE_DEFAULT);
            overriddenSensorPixelModesUsed->insert(ANDROID_SENSOR_PIXEL_MODE_MAXIMUM_RESOLUTION);
            return OK;
        }
        if (isInMaximumResolutionStreamConfigurationMap) {
            overriddenSensorPixelModesUsed->insert(
                    ANDROID_SENSOR_PIXEL_MODE_MAXIMUM_RESOLUTION);
        } else {
            overriddenSensorPixelModesUsed->insert(ANDROID_SENSOR_PIXEL_MODE_DEFAULT);
        }
        return OK;
    }

    // Case2: The app has set sensorPixelModesUsed, we need to verify that they
    // are valid / err out.
    if (sensorPixelModesUsedSet.find(ANDROID_SENSOR_PIXEL_MODE_DEFAULT) !=
            sensorPixelModesUsedSet.end() && !isInDefaultStreamConfigurationMap) {
        ALOGE("%s: ANDROID_SENSOR_PIXEL_MODE_DEFAULT set by client, but stream f: %d size %d x %d"
                " isn't present in default stream configuration map", __FUNCTION__, format, width,
                height);
        return BAD_VALUE;
    }

   if (sensorPixelModesUsedSet.find(ANDROID_SENSOR_PIXEL_MODE_MAXIMUM_RESOLUTION) !=
            sensorPixelModesUsedSet.end() && !isInMaximumResolutionStreamConfigurationMap) {
        ALOGE("%s: ANDROID_SENSOR_PIXEL_MODE_MAXIMUM_RESOLUTION set by client, but stream f: "
                "%d size %d x %d isn't present in default stream configuration map", __FUNCTION__,
                format, width, height);
        return BAD_VALUE;
    }
    *overriddenSensorPixelModesUsed = sensorPixelModesUsedSet;
    return OK;
}

bool targetPerfClassPrimaryCamera(
        const std::set<std::string>& perfClassPrimaryCameraIds, const std::string& cameraId,
        int targetSdkVersion) {
    bool isPerfClassPrimaryCamera =
            perfClassPrimaryCameraIds.find(cameraId) != perfClassPrimaryCameraIds.end();
    return targetSdkVersion >= SDK_VERSION_S && isPerfClassPrimaryCamera;
}

} // namespace SessionConfigurationUtils
} // namespace camera3
} // namespace android
