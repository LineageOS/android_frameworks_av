/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include "SessionConfigurationUtilsHost.h"

namespace android {
namespace camera3 {
namespace SessionConfigurationUtils {

int32_t getAppropriateModeTag(int32_t defaultTag, bool maxResolution) {
    if (!maxResolution) {
        return defaultTag;
    }
    switch (defaultTag) {
        case ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS:
            return ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS_MAXIMUM_RESOLUTION;
        case ANDROID_SCALER_AVAILABLE_MIN_FRAME_DURATIONS:
            return ANDROID_SCALER_AVAILABLE_MIN_FRAME_DURATIONS_MAXIMUM_RESOLUTION;
        case ANDROID_SCALER_AVAILABLE_STALL_DURATIONS:
            return ANDROID_SCALER_AVAILABLE_STALL_DURATIONS_MAXIMUM_RESOLUTION;
        case ANDROID_DEPTH_AVAILABLE_DEPTH_STREAM_CONFIGURATIONS:
            return ANDROID_DEPTH_AVAILABLE_DEPTH_STREAM_CONFIGURATIONS_MAXIMUM_RESOLUTION;
        case ANDROID_DEPTH_AVAILABLE_DEPTH_MIN_FRAME_DURATIONS:
            return ANDROID_DEPTH_AVAILABLE_DEPTH_MIN_FRAME_DURATIONS_MAXIMUM_RESOLUTION;
        case ANDROID_DEPTH_AVAILABLE_DEPTH_STALL_DURATIONS:
            return ANDROID_DEPTH_AVAILABLE_DEPTH_STALL_DURATIONS_MAXIMUM_RESOLUTION;
        case ANDROID_DEPTH_AVAILABLE_DYNAMIC_DEPTH_STREAM_CONFIGURATIONS:
            return ANDROID_DEPTH_AVAILABLE_DYNAMIC_DEPTH_STREAM_CONFIGURATIONS_MAXIMUM_RESOLUTION;
        case ANDROID_DEPTH_AVAILABLE_DYNAMIC_DEPTH_MIN_FRAME_DURATIONS:
            return ANDROID_DEPTH_AVAILABLE_DYNAMIC_DEPTH_MIN_FRAME_DURATIONS_MAXIMUM_RESOLUTION;
        case ANDROID_DEPTH_AVAILABLE_DYNAMIC_DEPTH_STALL_DURATIONS:
            return ANDROID_DEPTH_AVAILABLE_DYNAMIC_DEPTH_STALL_DURATIONS_MAXIMUM_RESOLUTION;
        case ANDROID_HEIC_AVAILABLE_HEIC_STREAM_CONFIGURATIONS:
            return ANDROID_HEIC_AVAILABLE_HEIC_STREAM_CONFIGURATIONS_MAXIMUM_RESOLUTION;
        case ANDROID_HEIC_AVAILABLE_HEIC_MIN_FRAME_DURATIONS:
            return ANDROID_HEIC_AVAILABLE_HEIC_MIN_FRAME_DURATIONS_MAXIMUM_RESOLUTION;
        case ANDROID_HEIC_AVAILABLE_HEIC_STALL_DURATIONS:
            return ANDROID_HEIC_AVAILABLE_HEIC_STALL_DURATIONS_MAXIMUM_RESOLUTION;
        case ANDROID_JPEGR_AVAILABLE_JPEG_R_STREAM_CONFIGURATIONS:
            return ANDROID_JPEGR_AVAILABLE_JPEG_R_STREAM_CONFIGURATIONS_MAXIMUM_RESOLUTION;
        case ANDROID_JPEGR_AVAILABLE_JPEG_R_MIN_FRAME_DURATIONS:
            return ANDROID_JPEGR_AVAILABLE_JPEG_R_MIN_FRAME_DURATIONS_MAXIMUM_RESOLUTION;
        case ANDROID_JPEGR_AVAILABLE_JPEG_R_STALL_DURATIONS:
            return ANDROID_JPEGR_AVAILABLE_JPEG_R_STALL_DURATIONS_MAXIMUM_RESOLUTION;
        case ANDROID_SENSOR_OPAQUE_RAW_SIZE:
            return ANDROID_SENSOR_OPAQUE_RAW_SIZE_MAXIMUM_RESOLUTION;
        case ANDROID_LENS_INTRINSIC_CALIBRATION:
            return ANDROID_LENS_INTRINSIC_CALIBRATION_MAXIMUM_RESOLUTION;
        case ANDROID_LENS_DISTORTION:
            return ANDROID_LENS_DISTORTION_MAXIMUM_RESOLUTION;
        case ANDROID_SENSOR_INFO_PRE_CORRECTION_ACTIVE_ARRAY_SIZE:
            return ANDROID_SENSOR_INFO_PRE_CORRECTION_ACTIVE_ARRAY_SIZE_MAXIMUM_RESOLUTION;
        case ANDROID_SENSOR_INFO_ACTIVE_ARRAY_SIZE:
            return ANDROID_SENSOR_INFO_ACTIVE_ARRAY_SIZE_MAXIMUM_RESOLUTION;
        default:
            ALOGE("%s: Tag %d doesn't have a maximum resolution counterpart", __FUNCTION__,
                    defaultTag);
            return -1;
    }
    return -1;
}

static bool isKeyPresentWithCount(const CameraMetadata &deviceInfo, uint32_t tag, uint32_t count) {
    auto countFound = deviceInfo.find(tag).count;
    return (countFound != 0) && (countFound % count == 0);
}

static bool supportsKeysForBasicUltraHighResolutionCapture(const CameraMetadata &deviceInfo) {
    // Check whether the following conditions are satisfied for reduced ultra high
    // resolution support :
    // 1) SENSOR_PIXEL_MODE is advertised in ANDROID_REQUEST_AVAILABLE_REQUEST_KEYS
    // 2) The following keys are present in CameraCharacteristics for basic functionality
    //        a) ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS_MAXIMUM_RESOLUTION
    //        b) ANDROID_SCALER_AVAILABLE_MIN_FRAME_DURATIONS_MAXIMUM_RESOLUTION
    //        c) ANDROID_SCALER_AVAILABLE_STALL_DURATIONS_MAXIMUM_RESOLUTION
    //        d) ANDROID_SENSOR_INFO_ACTIVE_ARRAY_SIZE_MAXIMUM_RESOLUTION
    //        e) ANDROID_SENSOR_INFO_PRE_CORRECTION_ACTIVE_ARRAY_SIZE_MAXIMUM_RESOLUTION
    //        f) ANDROID_SENSOR_INFO_PIXEL_ARRAY_SIZE_MAXIMUM_RESOLUTION
    camera_metadata_ro_entry_t entryChar;
    entryChar = deviceInfo.find(ANDROID_REQUEST_AVAILABLE_REQUEST_KEYS);
    bool supportsSensorPixelMode = false;
    for (size_t i = 0; i < entryChar.count; i++) {
        int32_t key = entryChar.data.i32[i];
        if (key == ANDROID_SENSOR_PIXEL_MODE) {
            supportsSensorPixelMode = true;
            break;
        }
    }
    if (!supportsSensorPixelMode) {
        return false;
    }

    // Basic sensor array size information tags are present
    if (!isKeyPresentWithCount(deviceInfo, ANDROID_SENSOR_INFO_PIXEL_ARRAY_SIZE_MAXIMUM_RESOLUTION,
            /*count*/2) ||
            !isKeyPresentWithCount(deviceInfo,
                    ANDROID_SENSOR_INFO_PRE_CORRECTION_ACTIVE_ARRAY_SIZE_MAXIMUM_RESOLUTION,
                    /*count*/4) ||
            !isKeyPresentWithCount(deviceInfo,
                    ANDROID_SENSOR_INFO_ACTIVE_ARRAY_SIZE_MAXIMUM_RESOLUTION, /*count*/4) ||
            !isKeyPresentWithCount(deviceInfo, ANDROID_SENSOR_INFO_BINNING_FACTOR, /*count*/2)) {
        return false;
    }

    // Basic stream configuration tags are present
    if (!isKeyPresentWithCount(deviceInfo,
            ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS_MAXIMUM_RESOLUTION, /*count*/4) ||
            !isKeyPresentWithCount(deviceInfo,
                    ANDROID_SCALER_AVAILABLE_MIN_FRAME_DURATIONS_MAXIMUM_RESOLUTION, /*count*/4) ||
            !isKeyPresentWithCount(deviceInfo,
                    ANDROID_SCALER_AVAILABLE_STALL_DURATIONS_MAXIMUM_RESOLUTION, /*count*/ 4)) {
        return false;
    }

    return true;
}

bool supportsUltraHighResolutionCapture(const CameraMetadata &deviceInfo) {
    camera_metadata_ro_entry_t entryCap;
    entryCap = deviceInfo.find(ANDROID_REQUEST_AVAILABLE_CAPABILITIES);
    // Go through the capabilities and check if it has
    // ANDROID_REQUEST_AVAILABLE_CAPABILITIES_ULTRA_HIGH_RESOLUTION_SENSOR
    for (size_t i = 0; i < entryCap.count; ++i) {
        uint8_t capability = entryCap.data.u8[i];
        if (capability == ANDROID_REQUEST_AVAILABLE_CAPABILITIES_ULTRA_HIGH_RESOLUTION_SENSOR) {
            return true;
        }
    }

    // If not, then check that the keys which guarantee basic supports for
    // ultra high resolution capture are supported.
    return supportsKeysForBasicUltraHighResolutionCapture(deviceInfo);
}

bool getArrayWidthAndHeight(const CameraMetadata *deviceInfo,
        int32_t arrayTag, int32_t *width, int32_t *height) {
    if (width == nullptr || height == nullptr) {
        ALOGE("%s: width / height nullptr", __FUNCTION__);
        return false;
    }
    camera_metadata_ro_entry_t entry;
    entry = deviceInfo->find(arrayTag);
    if (entry.count != 4) return false;
    *width = entry.data.i32[2];
    *height = entry.data.i32[3];
    return true;
}

} // namespace SessionConfigurationUtils
} // namespace camera3
} // namespace android
