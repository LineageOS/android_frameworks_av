/*
 * Copyright (C) 2018 The Android Open Source Project
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

#define LOG_TAG "ACameraVendorUtils"

#include "utils.h"

#include <utils/Log.h>

namespace android {
namespace acam {
namespace utils {

// Convert CaptureRequest wrappable by sp<> to aidl CaptureRequest.
AidlCaptureRequest convertToAidl(const CaptureRequest *captureRequest) {
    AidlCaptureRequest aidlCaptureRequest;
    aidlCaptureRequest.physicalCameraSettings =
            captureRequest->mCaptureRequest.physicalCameraSettings;
    aidlCaptureRequest.streamAndWindowIds = captureRequest->mCaptureRequest.streamAndWindowIds;
    return aidlCaptureRequest;
}

OutputConfiguration::Rotation convertToAidl(int rotation) {
    using AidlRotation = OutputConfiguration::Rotation;

    AidlRotation aRot = AidlRotation ::R0;
    switch(rotation) {
        case CAMERA3_STREAM_ROTATION_90:
            aRot = AidlRotation::R90;
            break;
        case CAMERA3_STREAM_ROTATION_180:
            aRot = AidlRotation::R180;
            break;
        case CAMERA3_STREAM_ROTATION_270:
            aRot = AidlRotation::R270;
            break;
        default:
            break;
    }
    return aRot;
}

bool cloneFromAidl(const AidlCameraMetadata& srcMetadata, camera_metadata_t** dst) {
    const camera_metadata *buffer = (camera_metadata_t*)(srcMetadata.metadata.data());
    size_t expectedSize = srcMetadata.metadata.size();
    int ret = validate_camera_metadata_structure(buffer, &expectedSize);
    if (ret != OK && ret != CAMERA_METADATA_VALIDATION_SHIFTED) {
        ALOGE("%s: Malformed camera srcMetadata received from caller", __FUNCTION__);
        return false;
    }

    camera_metadata_t* clonedBuffer = clone_camera_metadata(buffer);
    if (clonedBuffer != nullptr) {
        *dst = clonedBuffer;
        return true;
    }

    ALOGE("%s: Failed to clone srcMetadata buffer.", __FUNCTION__);
    return false;
}

// Note: existing data in dst will be gone.
void convertToAidl(const camera_metadata_t *src, AidlCameraMetadata* dst) {
    if (src == nullptr) {
        return;
    }
    size_t size = get_camera_metadata_size(src);
    uint8_t* metadataStart = (uint8_t*)src;
    uint8_t* metadataEnd = metadataStart + size;
    dst->metadata.assign(metadataStart, metadataEnd);
}

TemplateId convertToAidl(ACameraDevice_request_template templateId) {
    switch(templateId) {
        case TEMPLATE_STILL_CAPTURE:
            return TemplateId::STILL_CAPTURE;
        case TEMPLATE_RECORD:
            return TemplateId::RECORD;
        case TEMPLATE_VIDEO_SNAPSHOT:
            return TemplateId::VIDEO_SNAPSHOT;
        case TEMPLATE_ZERO_SHUTTER_LAG:
            return TemplateId::ZERO_SHUTTER_LAG;
        case TEMPLATE_MANUAL:
            return TemplateId::MANUAL;
        default:
            return TemplateId::PREVIEW;
    }
}

camera_status_t convertFromAidl(Status status) {
    camera_status_t ret = ACAMERA_OK;
    switch(status) {
        case Status::NO_ERROR:
            break;
        case Status::DISCONNECTED:
            ret = ACAMERA_ERROR_CAMERA_DISCONNECTED;
            break;
        case Status::CAMERA_IN_USE:
            ret = ACAMERA_ERROR_CAMERA_IN_USE;
            break;
        case Status::MAX_CAMERAS_IN_USE:
            ret = ACAMERA_ERROR_MAX_CAMERA_IN_USE;
            break;
        case Status::ILLEGAL_ARGUMENT:
            ret = ACAMERA_ERROR_INVALID_PARAMETER;
            break;
        case Status::DEPRECATED_HAL:
            // Should not reach here since we filtered legacy HALs earlier
            ret = ACAMERA_ERROR_INVALID_PARAMETER;
            break;
        case Status::DISABLED:
            ret = ACAMERA_ERROR_CAMERA_DISABLED;
            break;
        case Status::PERMISSION_DENIED:
            ret = ACAMERA_ERROR_PERMISSION_DENIED;
            break;
        case Status::INVALID_OPERATION:
            ret = ACAMERA_ERROR_INVALID_OPERATION;
            break;
        default:
            ret = ACAMERA_ERROR_UNKNOWN;
            break;
    }
    return ret;
}

} // namespace utils
} // namespace acam
} // namespace android
