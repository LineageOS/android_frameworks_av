/*
 * Copyright (C) 2022 The Android Open Source Project
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

#define LOG_TAG "AidlUtils"

#include <aidl/AidlUtils.h>
#include <aidl/ExtensionMetadataTags.h>
#include <aidl/VndkVersionMetadataTags.h>
#include <aidlcommonsupport/NativeHandle.h>
#include <camera/StringUtils.h>
#include <device3/Camera3StreamInterface.h>
#include <gui/bufferqueue/1.0/H2BGraphicBufferProducer.h>
#include <mediautils/AImageReaderUtils.h>

namespace android::hardware::cameraservice::utils::conversion::aidl {

using aimg::AImageReader_getHGBPFromHandle;
using hardware::graphics::bufferqueue::V1_0::utils::H2BGraphicBufferProducer;

// Note: existing data in dst will be gone. Caller still owns the memory of src
void cloneToAidl(const camera_metadata_t* src, SCameraMetadata* dst) {
    if (src == nullptr) {
        ALOGW("%s:attempt to convert empty metadata to AIDL", __FUNCTION__);
        return;
    }
    size_t size = get_camera_metadata_size(src);
    uint8_t* startPtr = (uint8_t*)src;
    uint8_t* endPtr = startPtr + size;
    dst->metadata.assign(startPtr, endPtr);
}

// The camera metadata here is cloned. Since we're reading metadata over
// the binder we would need to clone it in order to avoid alignment issues.
bool cloneFromAidl(const SCameraMetadata &src, CameraMetadata *dst) {
    const camera_metadata_t *buffer =
            reinterpret_cast<const camera_metadata_t*>(src.metadata.data());
    size_t expectedSize = src.metadata.size();
    if (buffer != nullptr) {
        int res = validate_camera_metadata_structure(buffer, &expectedSize);
        if (res == OK || res == CAMERA_METADATA_VALIDATION_SHIFTED) {
            *dst = buffer;
        } else {
            ALOGE("%s: Malformed camera metadata received from HAL", __FUNCTION__);
            return false;
        }
    }
    return true;
}

int32_t convertFromAidl(SStreamConfigurationMode streamConfigurationMode) {
    switch (streamConfigurationMode) {
        case SStreamConfigurationMode::CONSTRAINED_HIGH_SPEED_MODE:
            return camera2::ICameraDeviceUser::CONSTRAINED_HIGH_SPEED_MODE;
        case SStreamConfigurationMode::NORMAL_MODE:
            return camera2::ICameraDeviceUser::NORMAL_MODE;
        default:
            // TODO: Fix this
            return camera2::ICameraDeviceUser::VENDOR_MODE_START;
    }
}

UOutputConfiguration convertFromAidl(const SOutputConfiguration &src) {
    std::vector<sp<IGraphicBufferProducer>> iGBPs;
    if (!src.surfaces.empty()) {
        auto& surfaces = src.surfaces;
        iGBPs.reserve(surfaces.size());

        for (auto& sSurface : surfaces) {
            sp<IGraphicBufferProducer> igbp =
                    Surface::getIGraphicBufferProducer(sSurface.get());
            if (igbp == nullptr) {
                ALOGE("%s: ANativeWindow (%p) not backed by a Surface.",
                      __FUNCTION__, sSurface.get());
                continue;
            }
            iGBPs.push_back(igbp);
        }
    } else {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        // HIDL token manager (and consequently 'windowHandles') is deprecated and will be removed
        // in the future. However, cameraservice must still support old NativeHandle pathway until
        // all vendors have moved away from using NativeHandles
        auto &windowHandles = src.windowHandles;
#pragma clang diagnostic pop

        iGBPs.reserve(windowHandles.size());

        for (auto &handle : windowHandles) {
            native_handle_t* nh = makeFromAidl(handle);
            auto igbp = AImageReader_getHGBPFromHandle(nh);
            if (igbp == nullptr) {
                ALOGE("%s: Could not get HGBP from NativeHandle: %s. Skipping.",
                        __FUNCTION__, handle.toString().c_str());
                continue;
            }

            iGBPs.push_back(new H2BGraphicBufferProducer(igbp));
            native_handle_delete(nh);
        }
    }

    UOutputConfiguration outputConfiguration(
        iGBPs, convertFromAidl(src.rotation), src.physicalCameraId,
        src.windowGroupId, OutputConfiguration::SURFACE_TYPE_UNKNOWN, 0, 0,
        (iGBPs.size() > 1));
    return outputConfiguration;
}

USessionConfiguration convertFromAidl(const SSessionConfiguration &src) {
    USessionConfiguration sessionConfig(src.inputWidth, src.inputHeight,
                                        src.inputFormat, static_cast<int>(src.operationMode));

    for (const auto& os : src.outputStreams) {
        UOutputConfiguration config = convertFromAidl(os);
        sessionConfig.addOutputConfiguration(config);
    }

    return sessionConfig;
}

int convertFromAidl(SOutputConfiguration::Rotation rotation) {
    switch(rotation) {
        case SOutputConfiguration::Rotation::R270:
            return android::camera3::CAMERA_STREAM_ROTATION_270;
        case SOutputConfiguration::Rotation::R180:
            return android::camera3::CAMERA_STREAM_ROTATION_180;
        case SOutputConfiguration::Rotation::R90:
            return android::camera3::CAMERA_STREAM_ROTATION_90;
        case SOutputConfiguration::Rotation::R0:
        default:
            return android::camera3::CAMERA_STREAM_ROTATION_0;
    }
}

int32_t convertFromAidl(STemplateId templateId) {
    switch(templateId) {
        case STemplateId::PREVIEW:
            return camera2::ICameraDeviceUser::TEMPLATE_PREVIEW;
        case STemplateId::STILL_CAPTURE:
            return camera2::ICameraDeviceUser::TEMPLATE_STILL_CAPTURE;
        case STemplateId::RECORD:
            return camera2::ICameraDeviceUser::TEMPLATE_RECORD;
        case STemplateId::VIDEO_SNAPSHOT:
            return camera2::ICameraDeviceUser::TEMPLATE_VIDEO_SNAPSHOT;
        case STemplateId::ZERO_SHUTTER_LAG:
            return camera2::ICameraDeviceUser::TEMPLATE_ZERO_SHUTTER_LAG;
        case STemplateId::MANUAL:
            return camera2::ICameraDeviceUser::TEMPLATE_MANUAL;
    }
}

void convertToAidl(const camera2::utils::SubmitInfo& submitInfo, SSubmitInfo* hSubmitInfo) {
    hSubmitInfo->requestId = submitInfo.mRequestId;
    hSubmitInfo->lastFrameNumber = submitInfo.mLastFrameNumber;
}


SStatus convertToAidl(const binder::Status &status) {
    if (status.isOk()) {
        return SStatus::NO_ERROR;
    }
    if (status.exceptionCode() != EX_SERVICE_SPECIFIC) {
        return SStatus::UNKNOWN_ERROR;
    }

    switch (status.serviceSpecificErrorCode()) {
        case hardware::ICameraService::ERROR_DISCONNECTED:
            return SStatus::DISCONNECTED;
        case hardware::ICameraService::ERROR_CAMERA_IN_USE:
            return SStatus::CAMERA_IN_USE;
        case hardware::ICameraService::ERROR_MAX_CAMERAS_IN_USE:
            return SStatus::MAX_CAMERAS_IN_USE;
        case hardware::ICameraService::ERROR_ILLEGAL_ARGUMENT:
            return SStatus::ILLEGAL_ARGUMENT;
        case hardware::ICameraService::ERROR_DEPRECATED_HAL:
            // Should not reach here since we filtered legacy HALs earlier
            return SStatus::DEPRECATED_HAL;
        case hardware::ICameraService::ERROR_DISABLED:
            return SStatus::DISABLED;
        case hardware::ICameraService::ERROR_PERMISSION_DENIED:
            return SStatus::PERMISSION_DENIED;
        case hardware::ICameraService::ERROR_INVALID_OPERATION:
            return SStatus::INVALID_OPERATION;
        default:
            return SStatus::UNKNOWN_ERROR;
    }
}

SCaptureResultExtras convertToAidl(const UCaptureResultExtras &src) {
    SCaptureResultExtras dst;
    dst.requestId = src.requestId;
    dst.burstId = src.burstId;
    dst.frameNumber = src.frameNumber;
    dst.partialResultCount = src.partialResultCount;
    dst.errorStreamId = src.errorStreamId;
    dst.errorPhysicalCameraId = src.errorPhysicalCameraId;
    return dst;
}

SErrorCode convertToAidl(int32_t errorCode) {
    switch(errorCode) {
        case camera2::ICameraDeviceCallbacks::ERROR_CAMERA_DISCONNECTED:
            return SErrorCode::CAMERA_DISCONNECTED;
        case camera2::ICameraDeviceCallbacks::ERROR_CAMERA_DEVICE :
            return SErrorCode::CAMERA_DEVICE;
        case camera2::ICameraDeviceCallbacks::ERROR_CAMERA_SERVICE:
            return SErrorCode::CAMERA_SERVICE;
        case camera2::ICameraDeviceCallbacks::ERROR_CAMERA_REQUEST:
            return SErrorCode::CAMERA_REQUEST;
        case camera2::ICameraDeviceCallbacks::ERROR_CAMERA_RESULT:
            return SErrorCode::CAMERA_RESULT;
        case camera2::ICameraDeviceCallbacks::ERROR_CAMERA_BUFFER:
            return SErrorCode::CAMERA_BUFFER;
        case camera2::ICameraDeviceCallbacks::ERROR_CAMERA_DISABLED:
            return SErrorCode::CAMERA_DISABLED;
        case camera2::ICameraDeviceCallbacks::ERROR_CAMERA_INVALID_ERROR:
            return SErrorCode::CAMERA_INVALID_ERROR;
        default:
            return SErrorCode::CAMERA_UNKNOWN_ERROR;
    }
}

std::vector<SPhysicalCaptureResultInfo> convertToAidl(
        const std::vector<UPhysicalCaptureResultInfo>& src,
        std::shared_ptr<CaptureResultMetadataQueue>& fmq) {
    std::vector<SPhysicalCaptureResultInfo> dst;
    dst.resize(src.size());
    size_t i = 0;
    for (auto &physicalCaptureResultInfo : src) {
        dst[i++] = convertToAidl(physicalCaptureResultInfo, fmq);
    }
    return dst;
}

SPhysicalCaptureResultInfo convertToAidl(const UPhysicalCaptureResultInfo & src,
                                         std::shared_ptr<CaptureResultMetadataQueue> & fmq) {
    SPhysicalCaptureResultInfo dst;
    dst.physicalCameraId = src.mPhysicalCameraId;

    const camera_metadata_t *rawMetadata = src.mPhysicalCameraMetadata.getAndLock();
    // Try using fmq at first.
    size_t metadata_size = get_camera_metadata_size(rawMetadata);
    if ((metadata_size > 0) && (fmq->availableToWrite() > 0)) {
        if (fmq->write((int8_t *)rawMetadata, metadata_size)) {
            dst.physicalCameraMetadata.set<SCaptureMetadataInfo::fmqMetadataSize>(metadata_size);
        } else {
            ALOGW("%s Couldn't use fmq, falling back to hwbinder", __FUNCTION__);
            SCameraMetadata metadata;
            cloneToAidl(rawMetadata, &metadata);
            dst.physicalCameraMetadata.set<SCaptureMetadataInfo::metadata>(std::move(metadata));
        }
    }
    src.mPhysicalCameraMetadata.unlock(rawMetadata);
    return dst;
}

void convertToAidl(const std::vector<hardware::CameraStatus> &src,
                   std::vector<SCameraStatusAndId>* dst) {
    dst->resize(src.size());
    size_t i = 0;
    for (const auto &statusAndId : src) {
        auto &a = (*dst)[i++];
        a.cameraId = statusAndId.cameraId;
        a.deviceStatus = convertCameraStatusToAidl(statusAndId.status);
        size_t numUnvailPhysicalCameras = statusAndId.unavailablePhysicalIds.size();
        a.unavailPhysicalCameraIds.resize(numUnvailPhysicalCameras);
        for (size_t j = 0; j < numUnvailPhysicalCameras; j++) {
            a.unavailPhysicalCameraIds[j] = statusAndId.unavailablePhysicalIds[j];
        }
    }
}

SCameraDeviceStatus convertCameraStatusToAidl(int32_t src) {
    SCameraDeviceStatus deviceStatus = SCameraDeviceStatus::STATUS_UNKNOWN;
    switch(src) {
        case hardware::ICameraServiceListener::STATUS_NOT_PRESENT:
            deviceStatus = SCameraDeviceStatus::STATUS_NOT_PRESENT;
            break;
        case hardware::ICameraServiceListener::STATUS_PRESENT:
            deviceStatus = SCameraDeviceStatus::STATUS_PRESENT;
            break;
        case hardware::ICameraServiceListener::STATUS_ENUMERATING:
            deviceStatus = SCameraDeviceStatus::STATUS_ENUMERATING;
            break;
        case hardware::ICameraServiceListener::STATUS_NOT_AVAILABLE:
            deviceStatus = SCameraDeviceStatus::STATUS_NOT_AVAILABLE;
            break;
        default:
            break;
    }
    return deviceStatus;
}

bool areBindersEqual(const ndk::SpAIBinder& b1, const ndk::SpAIBinder& b2) {
    return !AIBinder_lt(b1.get(), b2.get()) && !AIBinder_lt(b2.get(), b1.get());
}

status_t filterVndkKeys(int vndkVersion, CameraMetadata &metadata, bool isStatic) {
    if (vndkVersion == __ANDROID_API_FUTURE__) {
        // VNDK version derived from ro.board.api_level is a version code-name that
        // corresponds to the current SDK version.
        return OK;
    }
    const auto &apiLevelToKeys =
            isStatic ? static_api_level_to_keys : dynamic_api_level_to_keys;
    // Find the vndk versions above the given vndk version. All the vndk
    // versions above the given one, need to have their keys filtered from the
    // metadata in order to avoid metadata invalidation.
    auto it = apiLevelToKeys.upper_bound(vndkVersion);
    while (it != apiLevelToKeys.end()) {
        for (const auto &key : it->second) {
            status_t res = metadata.erase(key);
            if (res != OK) {
                ALOGE("%s metadata key %d could not be erased", __FUNCTION__, key);
                return res;
            }
        }
        it++;
    }
    return OK;
}

bool areExtensionKeysSupported(const CameraMetadata& metadata) {
    auto requestKeys = metadata.find(ANDROID_REQUEST_AVAILABLE_REQUEST_KEYS);
    if (requestKeys.count == 0) {
        ALOGE("%s: No ANDROID_REQUEST_AVAILABLE_REQUEST_KEYS entries!", __FUNCTION__);
        return false;
    }

    auto resultKeys = metadata.find(ANDROID_REQUEST_AVAILABLE_RESULT_KEYS);
    if (resultKeys.count == 0) {
        ALOGE("%s: No ANDROID_REQUEST_AVAILABLE_RESULT_KEYS entries!", __FUNCTION__);
        return false;
    }

    for (const auto& extensionKey : extension_metadata_keys) {
        if (std::find(requestKeys.data.i32, requestKeys.data.i32 + requestKeys.count, extensionKey)
                != requestKeys.data.i32 + requestKeys.count) {
            return true;
        }

        if (std::find(resultKeys.data.i32, resultKeys.data.i32 + resultKeys.count, extensionKey)
                != resultKeys.data.i32 + resultKeys.count) {
            return true;
        }
    }

    return false;
}

status_t filterExtensionKeys(CameraMetadata* metadata /*out*/) {
    if (metadata == nullptr) {
        return BAD_VALUE;
    }

    for (const auto& key : extension_metadata_keys) {
        status_t res = metadata->erase(key);
        if (res != OK) {
            ALOGE("%s metadata key %d could not be erased", __FUNCTION__, key);
            return res;
        }
    }
    return OK;
}

} // namespace android::hardware::cameraservice::utils::conversion::aidl
