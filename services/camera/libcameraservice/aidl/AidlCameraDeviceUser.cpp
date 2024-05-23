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

#define LOG_TAG "AidlCameraDeviceUser"

#include "AidlCameraDeviceUser.h"
#include <aidl/AidlUtils.h>
#include <aidl/android/frameworks/cameraservice/device/CaptureMetadataInfo.h>
#include <android-base/properties.h>
#include <utils/Utils.h>

namespace android::frameworks::cameraservice::device::implementation {

// VNDK classes
using SCaptureMetadataInfo = ::aidl::android::frameworks::cameraservice::device::CaptureMetadataInfo;
// NDK classes
using UOutputConfiguration = ::android::hardware::camera2::params::OutputConfiguration;
using USessionConfiguration = ::android::hardware::camera2::params::SessionConfiguration;
using UStatus = ::android::binder::Status;
using USubmitInfo = ::android::hardware::camera2::utils::SubmitInfo;

using ::android::CameraMetadata;
using ::android::hardware::cameraservice::utils::conversion::aidl::cloneFromAidl;
using ::android::hardware::cameraservice::utils::conversion::aidl::cloneToAidl;
using ::android::hardware::cameraservice::utils::conversion::aidl::convertFromAidl;
using ::android::hardware::cameraservice::utils::conversion::aidl::convertToAidl;
using ::android::hardware::cameraservice::utils::conversion::aidl::filterVndkKeys;
using ::ndk::ScopedAStatus;

namespace {
constexpr int32_t CAMERA_REQUEST_METADATA_QUEUE_SIZE = 1 << 20 /* 1 MB */;
constexpr int32_t CAMERA_RESULT_METADATA_QUEUE_SIZE = 1 << 20 /* 1 MB */;

inline ScopedAStatus fromSStatus(const SStatus& s) {
    return s == SStatus::NO_ERROR ? ScopedAStatus::ok()
                                  : ScopedAStatus::fromServiceSpecificError(
                                            static_cast<int32_t>(s));
}
inline ScopedAStatus fromUStatus(const UStatus& status) {
    return status.isOk() ? ScopedAStatus::ok() : fromSStatus(convertToAidl(status));
}
} // anonymous namespace

AidlCameraDeviceUser::AidlCameraDeviceUser(const sp<UICameraDeviceUser>& deviceRemote):
      mDeviceRemote(deviceRemote) {
    mInitSuccess = initDevice();
    mVndkVersion = getVNDKVersionFromProp(__ANDROID_API_FUTURE__);
}

bool AidlCameraDeviceUser::initDevice() {
    // TODO: Get request and result metadata queue size from a system property.
    int32_t reqFMQSize = CAMERA_REQUEST_METADATA_QUEUE_SIZE;

    mCaptureRequestMetadataQueue =
        std::make_unique<CaptureRequestMetadataQueue>(static_cast<size_t>(reqFMQSize),
                                                      false /* non blocking */);
    if (!mCaptureRequestMetadataQueue->isValid()) {
        ALOGE("%s: invalid request fmq", __FUNCTION__);
        return false;
    }

    int32_t resFMQSize = CAMERA_RESULT_METADATA_QUEUE_SIZE;
    mCaptureResultMetadataQueue =
        std::make_shared<CaptureResultMetadataQueue>(static_cast<size_t>(resFMQSize),
                                                     false /* non blocking */);
    if (!mCaptureResultMetadataQueue->isValid()) {
        ALOGE("%s: invalid result fmq", __FUNCTION__);
        return false;
    }
    return true;
}

ndk::ScopedAStatus AidlCameraDeviceUser::getCaptureRequestMetadataQueue(
        MQDescriptor<int8_t, SynchronizedReadWrite>* _aidl_return) {
    if (mInitSuccess) {
        *_aidl_return = mCaptureRequestMetadataQueue->dupeDesc();
    }
    return ScopedAStatus::ok();
}

ndk::ScopedAStatus AidlCameraDeviceUser::getCaptureResultMetadataQueue(
        MQDescriptor<int8_t, SynchronizedReadWrite>* _aidl_return) {
    if (mInitSuccess) {
        *_aidl_return = mCaptureResultMetadataQueue->dupeDesc();
    }
    return ScopedAStatus::ok();
}

ndk::ScopedAStatus AidlCameraDeviceUser::prepare(int32_t in_streamId) {
    UStatus ret = mDeviceRemote->prepare(in_streamId);
    return fromUStatus(ret);
}

ndk::ScopedAStatus AidlCameraDeviceUser::submitRequestList(
        const std::vector<SCaptureRequest>& in_requestList, bool in_isRepeating,
        SSubmitInfo* _aidl_return) {
    USubmitInfo submitInfo;
    std::vector<UCaptureRequest> requests;
    for (const auto& req: in_requestList) {
        requests.emplace_back();
        if (!convertRequestFromAidl(req, &requests.back())) {
            ALOGE("%s: Failed to convert AIDL CaptureRequest.", __FUNCTION__);
            return fromSStatus(SStatus::ILLEGAL_ARGUMENT);
        }
    }
    UStatus ret = mDeviceRemote->submitRequestList(requests,
                                                   in_isRepeating, &submitInfo);
    if (!ret.isOk()) {
        ALOGE("%s: Failed submitRequestList to cameraservice: %s",
              __FUNCTION__, ret.toString8().c_str());
        return fromUStatus(ret);
    }
    mRequestId = submitInfo.mRequestId;
    convertToAidl(submitInfo, _aidl_return);
    return ScopedAStatus::ok();
}

ndk::ScopedAStatus AidlCameraDeviceUser::cancelRepeatingRequest(int64_t* _aidl_return) {
    UStatus ret = mDeviceRemote->cancelRequest(mRequestId, _aidl_return);
    return fromUStatus(ret);
}

ScopedAStatus AidlCameraDeviceUser::beginConfigure() {
    UStatus ret = mDeviceRemote->beginConfigure();
    return fromUStatus(ret);
}

ndk::ScopedAStatus AidlCameraDeviceUser::endConfigure(SStreamConfigurationMode in_operatingMode,
                                                      const SCameraMetadata& in_sessionParams,
                                                      int64_t in_startTimeNs) {
    CameraMetadata metadata;
    if (!cloneFromAidl(in_sessionParams, &metadata)) {
        return fromSStatus(SStatus::ILLEGAL_ARGUMENT);
    }

    std::vector<int32_t> offlineStreamIds;
    UStatus ret = mDeviceRemote->endConfigure(convertFromAidl(in_operatingMode),
                                              metadata, in_startTimeNs,
                                              &offlineStreamIds);
    return fromUStatus(ret);
}

ndk::ScopedAStatus AidlCameraDeviceUser::createStream(
        const SOutputConfiguration& in_outputConfiguration, int32_t* _aidl_return) {
    UOutputConfiguration outputConfig = convertFromAidl(in_outputConfiguration);
    int32_t newStreamId;
    UStatus ret = mDeviceRemote->createStream(outputConfig, &newStreamId);
    if (!ret.isOk()) {
        ALOGE("%s: Failed to create stream: %s", __FUNCTION__, ret.toString8().c_str());
    }
    *_aidl_return = newStreamId;
    return fromUStatus(ret);
}

ndk::ScopedAStatus AidlCameraDeviceUser::createDefaultRequest(STemplateId in_templateId,
                                                              SCameraMetadata* _aidl_return) {
    CameraMetadata metadata;
    UStatus ret = mDeviceRemote->createDefaultRequest(convertFromAidl(in_templateId),
                                                      &metadata);
    if (!ret.isOk()) {
        ALOGE("%s: Failed to create default request: %s", __FUNCTION__, ret.toString8().c_str());
        return fromUStatus(ret);
    }

    if (filterVndkKeys(mVndkVersion, metadata, /*isStatic*/false) != OK) {
        ALOGE("%s: Unable to filter vndk metadata keys for version %d",
              __FUNCTION__, mVndkVersion);
        return fromSStatus(SStatus::UNKNOWN_ERROR);
    }

    const camera_metadata_t* rawMetadata = metadata.getAndLock();
    cloneToAidl(rawMetadata, _aidl_return);
    metadata.unlock(rawMetadata);
    return ScopedAStatus::ok();
}

ndk::ScopedAStatus AidlCameraDeviceUser::waitUntilIdle() {
    UStatus ret = mDeviceRemote->waitUntilIdle();
    return fromUStatus(ret);
}

ndk::ScopedAStatus AidlCameraDeviceUser::flush(int64_t* _aidl_return) {
    UStatus ret = mDeviceRemote->flush(_aidl_return);
    return fromUStatus(ret);
}

ndk::ScopedAStatus AidlCameraDeviceUser::updateOutputConfiguration(
        int32_t in_streamId, const SOutputConfiguration& in_outputConfiguration) {
    UOutputConfiguration outputConfig = convertFromAidl(in_outputConfiguration);
    UStatus ret = mDeviceRemote->updateOutputConfiguration(in_streamId, outputConfig);
    if (!ret.isOk()) {
        ALOGE("%s: Failed to update output config for stream id: %d: %s",
              __FUNCTION__, in_streamId, ret.toString8().c_str());
    }
    return fromUStatus(ret);
}
ndk::ScopedAStatus AidlCameraDeviceUser::isSessionConfigurationSupported(
        const SSessionConfiguration& in_sessionConfiguration, bool* _aidl_return) {
    USessionConfiguration sessionConfig = convertFromAidl(in_sessionConfiguration);
    UStatus ret = mDeviceRemote->isSessionConfigurationSupported(sessionConfig,
                                                                 _aidl_return);
    return fromUStatus(ret);
}
ndk::ScopedAStatus AidlCameraDeviceUser::deleteStream(int32_t in_streamId) {
    UStatus ret = mDeviceRemote->deleteStream(in_streamId);
    return fromUStatus(ret);
}
ndk::ScopedAStatus AidlCameraDeviceUser::disconnect() {
    UStatus ret = mDeviceRemote->disconnect();
    return fromUStatus(ret);
}
bool AidlCameraDeviceUser::convertRequestFromAidl(
        const SCaptureRequest& src, UCaptureRequest* dst) {
    dst->mIsReprocess = false;
    for (const auto& streamAndWindowId : src.streamAndWindowIds) {
        dst->mStreamIdxList.push_back(streamAndWindowId.streamId);
        dst->mSurfaceIdxList.push_back(streamAndWindowId.windowId);
    }

    return copyPhysicalCameraSettings(src.physicalCameraSettings,
                                      &(dst->mPhysicalCameraSettings));
}
bool AidlCameraDeviceUser::copyPhysicalCameraSettings(
        const std::vector<SPhysicalCameraSettings>& src,
        std::vector<UCaptureRequest::PhysicalCameraSettings>* dst) {
    bool converted = false;
    for (auto &e : src) {
        dst->emplace_back();
        CaptureRequest::PhysicalCameraSettings &physicalCameraSetting =
            dst->back();
        physicalCameraSetting.id = e.id;

        // Read the settings either from the fmq or straightaway from the
        // request. We don't need any synchronization, since submitRequestList
        // is guaranteed to be called serially by the client if it decides to
        // use fmq.
        if (e.settings.getTag() == SCaptureMetadataInfo::fmqMetadataSize) {
            /**
             * Get settings from the fmq.
             */
            SCameraMetadata settingsFmq;
            int64_t metadataSize = e.settings.get<SCaptureMetadataInfo::fmqMetadataSize>();
            settingsFmq.metadata.resize(metadataSize);
            int8_t* metadataPtr = (int8_t*) settingsFmq.metadata.data();
            bool read = mCaptureRequestMetadataQueue->read(metadataPtr,
                                                           metadataSize);
            if (!read) {
                ALOGE("%s capture request settings could't be read from fmq size", __FUNCTION__);
                converted = false;
            } else {
                converted = cloneFromAidl(settingsFmq, &physicalCameraSetting.settings);
            }
        } else {
            /**
             * The settings metadata is contained in request settings field.
             */
            converted = cloneFromAidl(e.settings.get<SCaptureMetadataInfo::metadata>(),
                    &physicalCameraSetting.settings);
        }
        if (!converted) {
          ALOGE("%s: Unable to convert physicalCameraSettings from HIDL to AIDL.", __FUNCTION__);
          return false;
        }
    }
    return true;
}

} // namespace android::frameworks::cameraservice::device::implementation