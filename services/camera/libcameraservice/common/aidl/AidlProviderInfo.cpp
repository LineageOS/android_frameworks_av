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
#include "AidlProviderInfo.h"
#include "common/HalConversionsTemplated.h"
#include "common/CameraProviderInfoTemplated.h"

#include <cutils/properties.h>

#include <aidlcommonsupport/NativeHandle.h>
#include <android/binder_manager.h>
#include <android/hardware/ICameraService.h>
#include <camera_metadata_hidden.h>

#include "device3/ZoomRatioMapper.h"
#include <utils/SessionConfigurationUtils.h>
#include <utils/Trace.h>

namespace {
const bool kEnableLazyHal(property_get_bool("ro.camera.enableLazyHal", false));
} // anonymous namespace

namespace android {

namespace SessionConfigurationUtils = ::android::camera3::SessionConfigurationUtils;

using namespace aidl::android::hardware;
using namespace hardware::camera;
using hardware::camera2::utils::CameraIdAndSessionConfiguration;
using hardware::ICameraService;

using HalDeviceStatusType = aidl::android::hardware::camera::common::CameraDeviceStatus;
using ICameraProvider = aidl::android::hardware::camera::provider::ICameraProvider;
using StatusListener = CameraProviderManager::StatusListener;

static status_t mapExceptionCodeToStatusT(binder_exception_t binderException) {
    switch (binderException) {
        case EX_NONE:
            return OK;
        case EX_ILLEGAL_ARGUMENT:
        case EX_NULL_POINTER:
        case EX_BAD_PARCELABLE:
        case EX_ILLEGAL_STATE:
            return BAD_VALUE;
        case EX_UNSUPPORTED_OPERATION:
            return INVALID_OPERATION;
        case EX_TRANSACTION_FAILED:
            return DEAD_OBJECT;
        default:
            return UNKNOWN_ERROR;
    }
}

status_t AidlProviderInfo::mapToStatusT(const ndk::ScopedAStatus& s) {
    using Status = aidl::android::hardware::camera::common::Status;
    auto exceptionCode = s.getExceptionCode();
    if (exceptionCode != EX_SERVICE_SPECIFIC) {
        return mapExceptionCodeToStatusT(exceptionCode);
    }
    Status st = static_cast<Status>(s.getServiceSpecificError());
    switch (st) {
        case Status::OK:
            return OK;
        case Status::ILLEGAL_ARGUMENT:
            return BAD_VALUE;
        case Status::CAMERA_IN_USE:
            return -EBUSY;
        case Status::MAX_CAMERAS_IN_USE:
            return -EUSERS;
        case Status::OPERATION_NOT_SUPPORTED:
            return INVALID_OPERATION;
        case Status::CAMERA_DISCONNECTED:
            return DEAD_OBJECT;
        case Status::INTERNAL_ERROR:
            return INVALID_OPERATION;
    }
    ALOGW("Unexpected HAL status code %d", static_cast<int>(st));
    return INVALID_OPERATION;
}

AidlProviderInfo::AidlProviderInfo(
            const std::string &providerName,
            const std::string &providerInstance,
            CameraProviderManager *manager) :
            CameraProviderManager::ProviderInfo(providerName, providerInstance, manager) {}

status_t AidlProviderInfo::initializeAidlProvider(
        std::shared_ptr<ICameraProvider>& interface, int64_t currentDeviceState) {

    status_t res = parseProviderName(mProviderName, &mType, &mId);
    if (res != OK) {
        ALOGE("%s: Invalid provider name, ignoring", __FUNCTION__);
        return BAD_VALUE;
    }
    ALOGI("Connecting to new camera provider: %s, isRemote? %d",
            mProviderName.c_str(), interface->isRemote());

    // cameraDeviceStatusChange callbacks may be called (and causing new devices added)
    // before setCallback returns
    mCallbacks =
            ndk::SharedRefBase::make<AidlProviderCallbacks>(this);
    ndk::ScopedAStatus status =
            interface->setCallback(mCallbacks);
    if (!status.isOk()) {
        ALOGE("%s: Transaction error setting up callbacks with camera provider '%s': %s",
                __FUNCTION__, mProviderName.c_str(), status.getMessage());
        return mapToStatusT(status);
    }

    mDeathRecipient = ndk::ScopedAIBinder_DeathRecipient(AIBinder_DeathRecipient_new(binderDied));
    auto link = AIBinder_linkToDeath(interface->asBinder().get(), mDeathRecipient.get(), this);
    if (link != STATUS_OK) {
        ALOGW("%s: Unable to link to provider '%s' death notifications",
                __FUNCTION__, mProviderName.c_str());
        return DEAD_OBJECT;
    }

    if (!kEnableLazyHal) {
        // Save HAL reference indefinitely
        mSavedInterface = interface;
    } else {
        mActiveInterface = interface;
    }

    ALOGV("%s: Setting device state for %s: 0x%" PRIx64,
            __FUNCTION__, mProviderName.c_str(), mDeviceState);
    notifyDeviceStateChange(currentDeviceState);

    res = setUpVendorTags();
    if (res != OK) {
        ALOGE("%s: Unable to set up vendor tags from provider '%s'",
                __FUNCTION__, mProviderName.c_str());
        return res;
     }

    // Get initial list of camera devices, if any
    std::vector<std::string> devices;
    std::vector<std::string> retDevices;
    status = interface->getCameraIdList(&retDevices);
    if (!status.isOk()) {
        ALOGE("%s: Transaction error in getting camera ID list from provider '%s': %s",
                __FUNCTION__, mProviderName.c_str(), status.getMessage());
        return mapToStatusT(status);
    }

    for (auto& name : retDevices) {
        uint16_t major, minor;
        std::string type, id;
        status_t res = parseDeviceName(name, &major, &minor, &type, &id);
        if (res != OK) {
            ALOGE("%s: Error parsing deviceName: %s: %d", __FUNCTION__, name.c_str(), res);
            return res;
        } else {
            devices.push_back(name);
            mProviderPublicCameraIds.push_back(id);
        }
    }

    // Get list of concurrent streaming camera device combinations
    res = getConcurrentCameraIdsInternalLocked(interface);
    if (res != OK) {
        return res;
    }

    mSetTorchModeSupported = true;

    mIsRemote = interface->isRemote();

    initializeProviderInfoCommon(devices);
    return OK;
}

void AidlProviderInfo::binderDied(void *cookie) {
    AidlProviderInfo *provider = reinterpret_cast<AidlProviderInfo *>(cookie);
    ALOGI("Camera provider '%s' has died; removing it", provider->mProviderInstance.c_str());
    provider->mManager->removeProvider(provider->mProviderInstance);
}

status_t AidlProviderInfo::setUpVendorTags() {
    if (mVendorTagDescriptor != nullptr)
        return OK;

    std::vector<camera::common::VendorTagSection> vts;
    ::ndk::ScopedAStatus status;
    const std::shared_ptr<ICameraProvider> interface = startProviderInterface();
    if (interface == nullptr) {
        return DEAD_OBJECT;
    }
    status = interface->getVendorTags(&vts);
    if (!status.isOk()) {
        ALOGE("%s: Transaction error getting vendor tags from provider '%s': %s",
                __FUNCTION__, mProviderName.c_str(), status.getMessage());
        return mapToStatusT(status);
    }

    // Read all vendor tag definitions into a descriptor
    status_t res;
    if ((res =
            IdlVendorTagDescriptor::
                    createDescriptorFromIdl<std::vector<camera::common::VendorTagSection>,
                            camera::common::VendorTagSection>(vts, /*out*/mVendorTagDescriptor))
            != OK) {
        ALOGE("%s: Could not generate descriptor from vendor tag operations,"
                "received error %s (%d). Camera clients will not be able to use"
                "vendor tags", __FUNCTION__, strerror(res), res);
        return res;
    }

    return OK;
}

status_t AidlProviderInfo::notifyDeviceStateChange(int64_t newDeviceState) {

    mDeviceState = newDeviceState;
    // Check if the provider is currently active - not going to start it up for this notification
    auto interface = mSavedInterface != nullptr ? mSavedInterface : mActiveInterface.lock();
    if (interface != nullptr) {
        // Send current device state
        interface->notifyDeviceStateChange(mDeviceState);
    }
    return OK;
}

bool AidlProviderInfo::successfullyStartedProviderInterface() {
    return startProviderInterface() != nullptr;
}

std::shared_ptr<camera::device::ICameraDevice>
AidlProviderInfo::startDeviceInterface(const std::string &name) {
    ::ndk::ScopedAStatus status;
    std::shared_ptr<camera::device::ICameraDevice> cameraInterface;
    const std::shared_ptr<ICameraProvider> interface = startProviderInterface();
    if (interface == nullptr) {
        return nullptr;
    }
    status = interface->getCameraDeviceInterface(name, &cameraInterface);
    if (!status.isOk()) {
        ALOGE("%s: Transaction error trying to obtain interface for camera device %s: %s",
                __FUNCTION__, name.c_str(), status.getMessage());
        return nullptr;
    }
    return cameraInterface;
}

const std::shared_ptr<ICameraProvider> AidlProviderInfo::startProviderInterface() {
    ATRACE_CALL();
    ALOGV("Request to start camera provider: %s", mProviderName.c_str());
    if (mSavedInterface != nullptr) {
        return mSavedInterface;
    }
    if (!kEnableLazyHal) {
        ALOGE("Bad provider state! Should not be here on a non-lazy HAL!");
        return nullptr;
    }

    auto interface = mActiveInterface.lock();
    if (interface == nullptr) {
        // Try to get service without starting
        interface =
                    ICameraProvider::fromBinder(
                            ndk::SpAIBinder(AServiceManager_checkService(mProviderName.c_str())));
        if (interface == nullptr) {
            ALOGV("Camera provider actually needs restart, calling getService(%s)",
                  mProviderName.c_str());
            interface =
                            ICameraProvider::fromBinder(
                                    ndk::SpAIBinder(
                                                AServiceManager_getService(mProviderName.c_str())));

            // Set all devices as ENUMERATING, provider should update status
            // to PRESENT after initializing.
            // This avoids failing getCameraDeviceInterface_V3_x before devices
            // are ready.
            for (auto& device : mDevices) {
              device->mIsDeviceAvailable = false;
            }

            interface->setCallback(mCallbacks);
            auto link = AIBinder_linkToDeath(interface->asBinder().get(), mDeathRecipient.get(),
                    this);
            if (link != STATUS_OK) {
                ALOGW("%s: Unable to link to provider '%s' death notifications",
                        __FUNCTION__, mProviderName.c_str());
                mManager->removeProvider(mProviderName);
                return nullptr;
            }

            // Send current device state
            interface->notifyDeviceStateChange(mDeviceState);
        }
        mActiveInterface = interface;
    } else {
        ALOGV("Camera provider (%s) already in use. Re-using instance.",
              mProviderName.c_str());
    }

    return interface;
}

::ndk::ScopedAStatus AidlProviderInfo::AidlProviderCallbacks::cameraDeviceStatusChange(
    const std::string& cameraDeviceName,
    HalDeviceStatusType newStatus) {
    sp<AidlProviderInfo> parent = mParent.promote();
    if (parent == nullptr) {
        ALOGE("%s: Parent provider not alive", __FUNCTION__);
        return ::ndk::ScopedAStatus::ok();
    }
    return parent->cameraDeviceStatusChange(cameraDeviceName, newStatus);
}

::ndk::ScopedAStatus AidlProviderInfo::AidlProviderCallbacks::torchModeStatusChange(
            const std::string& cameraDeviceName,
            aidl::android::hardware::camera::common::TorchModeStatus newStatus) {
    sp<AidlProviderInfo> parent = mParent.promote();
    if (parent == nullptr) {
        ALOGE("%s: Parent provider not alive", __FUNCTION__);
        return ::ndk::ScopedAStatus::ok();
    }
    return parent->torchModeStatusChange(cameraDeviceName, newStatus);

};

::ndk::ScopedAStatus AidlProviderInfo::AidlProviderCallbacks::physicalCameraDeviceStatusChange(
            const std::string& cameraDeviceName,
            const std::string& physicalCameraDeviceName,
            HalDeviceStatusType newStatus) {
    sp<AidlProviderInfo> parent = mParent.promote();
    if (parent == nullptr) {
        ALOGE("%s: Parent provider not alive", __FUNCTION__);
        return ::ndk::ScopedAStatus::ok();
    }
    return parent->physicalCameraDeviceStatusChange(cameraDeviceName, physicalCameraDeviceName,
            newStatus);
};

::ndk::ScopedAStatus AidlProviderInfo::cameraDeviceStatusChange(const std::string& cameraDeviceName,
            HalDeviceStatusType newStatus) {
    cameraDeviceStatusChangeInternal(cameraDeviceName, HalToFrameworkCameraDeviceStatus(newStatus));
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus AidlProviderInfo::torchModeStatusChange(const std::string& cameraDeviceName,
            aidl::android::hardware::camera::common::TorchModeStatus newStatus) {
    torchModeStatusChangeInternal(cameraDeviceName, HalToFrameworkTorchModeStatus(newStatus));
    return ::ndk::ScopedAStatus::ok();
};

::ndk::ScopedAStatus AidlProviderInfo::physicalCameraDeviceStatusChange(
            const std::string& cameraDeviceName,
            const std::string& physicalCameraDeviceName,
            HalDeviceStatusType newStatus) {
    physicalCameraDeviceStatusChangeInternal(cameraDeviceName, physicalCameraDeviceName,
            HalToFrameworkCameraDeviceStatus(newStatus));
    return ::ndk::ScopedAStatus::ok();
};

std::unique_ptr<CameraProviderManager::ProviderInfo::DeviceInfo>
    AidlProviderInfo::initializeDeviceInfo(
        const std::string &name, const metadata_vendor_id_t tagId,
        const std::string &id, uint16_t minorVersion) {
    ::ndk::ScopedAStatus status;

    auto cameraInterface = startDeviceInterface(name);
    if (cameraInterface == nullptr) return nullptr;

    camera::common::CameraResourceCost resourceCost;
    status = cameraInterface->getResourceCost(&resourceCost);
    if (!status.isOk()) {
        ALOGE("%s: Unable to obtain resource costs for camera device %s: %s", __FUNCTION__,
                name.c_str(), status.getMessage());
        return nullptr;
    }

    for (auto& conflictName : resourceCost.conflictingDevices) {
        uint16_t major, minor;
        std::string type, id;
        status_t res = parseDeviceName(conflictName, &major, &minor, &type, &id);
        if (res != OK) {
            ALOGE("%s: Failed to parse conflicting device %s", __FUNCTION__, conflictName.c_str());
            return nullptr;
        }
        conflictName = id;
    }

    return std::unique_ptr<DeviceInfo3>(
        new AidlDeviceInfo3(name, tagId, id, minorVersion, HalToFrameworkResourceCost(resourceCost),
                this, mProviderPublicCameraIds, cameraInterface));
}

status_t AidlProviderInfo::reCacheConcurrentStreamingCameraIdsLocked() {

    // Check if the provider is currently active - not going to start it up for this notification
    auto interface = mSavedInterface != nullptr ? mSavedInterface : mActiveInterface.lock();
    if (interface == nullptr) {
        ALOGE("%s: camera provider interface for %s is not valid", __FUNCTION__,
                mProviderName.c_str());
        return INVALID_OPERATION;
    }

    return getConcurrentCameraIdsInternalLocked(interface);
}

status_t AidlProviderInfo::getConcurrentCameraIdsInternalLocked(
        std::shared_ptr<ICameraProvider> &interface) {
    if (interface == nullptr) {
        ALOGE("%s: null interface provided", __FUNCTION__);
        return BAD_VALUE;
    }

    std::vector<aidl::android::hardware::camera::provider::ConcurrentCameraIdCombination> combs;
    ::ndk::ScopedAStatus status = interface->getConcurrentCameraIds(&combs);

    if (!status.isOk()) {
        ALOGE("%s: Transaction error in getting concurrent camera ID list from provider '%s'",
                __FUNCTION__, mProviderName.c_str());
        return mapToStatusT(status);
    }
    mConcurrentCameraIdCombinations.clear();
    for (const auto& combination : combs) {
        std::unordered_set<std::string> deviceIds;
        for (const auto &cameraDeviceId : combination.combination) {
            deviceIds.insert(cameraDeviceId.c_str());
        }
        mConcurrentCameraIdCombinations.push_back(std::move(deviceIds));
    }

    return OK;
}

AidlProviderInfo::AidlDeviceInfo3::AidlDeviceInfo3(
        const std::string& name,
        const metadata_vendor_id_t tagId,
        const std::string &id, uint16_t minorVersion,
        const CameraResourceCost& resourceCost,
        sp<CameraProviderManager::ProviderInfo> parentProvider,
        const std::vector<std::string>& publicCameraIds,
        std::shared_ptr<aidl::android::hardware::camera::device::ICameraDevice> interface) :
        DeviceInfo3(name, tagId, id, minorVersion, resourceCost, parentProvider, publicCameraIds) {

    // Get camera characteristics and initialize flash unit availability
    aidl::android::hardware::camera::device::CameraMetadata chars;
    ::ndk::ScopedAStatus status = interface->getCameraCharacteristics(&chars);
    std::vector<uint8_t> &metadata = chars.metadata;
    camera_metadata_t *buffer = reinterpret_cast<camera_metadata_t*>(metadata.data());
    size_t expectedSize = metadata.size();
    int resV = validate_camera_metadata_structure(buffer, &expectedSize);
    if (resV == OK || resV == CAMERA_METADATA_VALIDATION_SHIFTED) {
        set_camera_metadata_vendor_id(buffer, mProviderTagid);
        mCameraCharacteristics = buffer;
    } else {
        ALOGE("%s: Malformed camera metadata received from HAL", __FUNCTION__);
        return;
    }

    if (!status.isOk()) {
        ALOGE("%s: Transaction error getting camera characteristics for device %s"
                " to check for a flash unit: %s", __FUNCTION__, id.c_str(),
                status.getMessage());
        return;
    }

    if (mCameraCharacteristics.exists(ANDROID_INFO_DEVICE_STATE_ORIENTATIONS)) {
        const auto &stateMap = mCameraCharacteristics.find(ANDROID_INFO_DEVICE_STATE_ORIENTATIONS);
        if ((stateMap.count > 0) && ((stateMap.count % 2) == 0)) {
            for (size_t i = 0; i < stateMap.count; i += 2) {
                mDeviceStateOrientationMap.emplace(stateMap.data.i64[i], stateMap.data.i64[i+1]);
            }
        } else {
            ALOGW("%s: Invalid ANDROID_INFO_DEVICE_STATE_ORIENTATIONS map size: %zu", __FUNCTION__,
                    stateMap.count);
        }
    }

    mSystemCameraKind = getSystemCameraKind();

    status_t res = fixupMonochromeTags();
    if (OK != res) {
        ALOGE("%s: Unable to fix up monochrome tags based for older HAL version: %s (%d)",
                __FUNCTION__, strerror(-res), res);
        return;
    }
    auto stat = addDynamicDepthTags();
    if (OK != stat) {
        ALOGE("%s: Failed appending dynamic depth tags: %s (%d)", __FUNCTION__, strerror(-stat),
                stat);
    }
    res = deriveHeicTags();
    if (OK != res) {
        ALOGE("%s: Unable to derive HEIC tags based on camera and media capabilities: %s (%d)",
                __FUNCTION__, strerror(-res), res);
    }

    if (camera3::SessionConfigurationUtils::isUltraHighResolutionSensor(mCameraCharacteristics)) {
        status_t status = addDynamicDepthTags(/*maxResolution*/true);
        if (OK != status) {
            ALOGE("%s: Failed appending dynamic depth tags for maximum resolution mode: %s (%d)",
                    __FUNCTION__, strerror(-status), status);
        }

        status = deriveHeicTags(/*maxResolution*/true);
        if (OK != status) {
            ALOGE("%s: Unable to derive HEIC tags based on camera and media capabilities for"
                    "maximum resolution mode: %s (%d)", __FUNCTION__, strerror(-status), status);
        }
    }

    res = addRotateCropTags();
    if (OK != res) {
        ALOGE("%s: Unable to add default SCALER_ROTATE_AND_CROP tags: %s (%d)", __FUNCTION__,
                strerror(-res), res);
    }
    res = addPreCorrectionActiveArraySize();
    if (OK != res) {
        ALOGE("%s: Unable to add PRE_CORRECTION_ACTIVE_ARRAY_SIZE: %s (%d)", __FUNCTION__,
                strerror(-res), res);
    }
    res = camera3::ZoomRatioMapper::overrideZoomRatioTags(
            &mCameraCharacteristics, &mSupportNativeZoomRatio);
    if (OK != res) {
        ALOGE("%s: Unable to override zoomRatio related tags: %s (%d)",
                __FUNCTION__, strerror(-res), res);
    }
    res = addReadoutTimestampTag();
    if (OK != res) {
        ALOGE("%s: Unable to add sensorReadoutTimestamp tag: %s (%d)",
                __FUNCTION__, strerror(-res), res);
    }

    camera_metadata_entry flashAvailable =
            mCameraCharacteristics.find(ANDROID_FLASH_INFO_AVAILABLE);
    if (flashAvailable.count == 1 &&
            flashAvailable.data.u8[0] == ANDROID_FLASH_INFO_AVAILABLE_TRUE) {
        mHasFlashUnit = true;
        // Fix up flash strength tags for devices without these keys.
        res = fixupTorchStrengthTags();
        if (OK != res) {
            ALOGE("%s: Unable to add default ANDROID_FLASH_INFO_STRENGTH_DEFAULT_LEVEL and"
                    "ANDROID_FLASH_INFO_STRENGTH_MAXIMUM_LEVEL tags: %s (%d)", __FUNCTION__,
                    strerror(-res), res);
        }
    } else {
        mHasFlashUnit = false;
    }

    camera_metadata_entry entry =
            mCameraCharacteristics.find(ANDROID_FLASH_INFO_STRENGTH_DEFAULT_LEVEL);
    if (entry.count == 1) {
        mTorchDefaultStrengthLevel = entry.data.i32[0];
    } else {
        mTorchDefaultStrengthLevel = 0;
    }
    entry = mCameraCharacteristics.find(ANDROID_FLASH_INFO_STRENGTH_MAXIMUM_LEVEL);
    if (entry.count == 1) {
        mTorchMaximumStrengthLevel = entry.data.i32[0];
    } else {
        mTorchMaximumStrengthLevel = 0;
    }

    mTorchStrengthLevel = 0;

    queryPhysicalCameraIds();

    // Get physical camera characteristics if applicable
    if (mIsLogicalCamera) {
        for (auto& id : mPhysicalIds) {
            if (std::find(mPublicCameraIds.begin(), mPublicCameraIds.end(), id) !=
                    mPublicCameraIds.end()) {
                continue;
            }

            aidl::android::hardware::camera::device::CameraMetadata pChars;
            status = interface->getPhysicalCameraCharacteristics(id, &pChars);
            if (!status.isOk()) {
                ALOGE("%s: Transaction error getting physical camera %s characteristics for %s: %s",
                        __FUNCTION__, id.c_str(), id.c_str(), status.getMessage());
                return;
            }
            std::vector<uint8_t> &pMetadata = pChars.metadata;
            camera_metadata_t *pBuffer =
                    reinterpret_cast<camera_metadata_t*>(pMetadata.data());
            size_t expectedSize = pMetadata.size();
            int res = validate_camera_metadata_structure(pBuffer, &expectedSize);
            if (res == OK || res == CAMERA_METADATA_VALIDATION_SHIFTED) {
                set_camera_metadata_vendor_id(pBuffer, mProviderTagid);
                mPhysicalCameraCharacteristics[id] = pBuffer;
            } else {
                ALOGE("%s: Malformed camera metadata received from HAL", __FUNCTION__);
                return;
            }

            res = camera3::ZoomRatioMapper::overrideZoomRatioTags(
                    &mPhysicalCameraCharacteristics[id], &mSupportNativeZoomRatio);
            if (OK != res) {
                ALOGE("%s: Unable to override zoomRatio related tags: %s (%d)",
                        __FUNCTION__, strerror(-res), res);
            }
        }
    }

    if (!kEnableLazyHal) {
        // Save HAL reference indefinitely
        mSavedInterface = interface;
    }
}

status_t AidlProviderInfo::AidlDeviceInfo3::setTorchMode(bool enabled) {
    const std::shared_ptr<camera::device::ICameraDevice> interface = startDeviceInterface();
    ::ndk::ScopedAStatus s = interface->setTorchMode(enabled);
    if (!s.isOk()) {
        ALOGE("%s Unable to set torch mode: %s", __FUNCTION__, s.getMessage());
        return mapToStatusT(s);
    }
    return OK;
}

status_t AidlProviderInfo::AidlDeviceInfo3::turnOnTorchWithStrengthLevel(
        int32_t torchStrength) {
    const std::shared_ptr<camera::device::ICameraDevice> interface = startDeviceInterface();
    if (interface == nullptr) {
        return DEAD_OBJECT;
    }

    ::ndk::ScopedAStatus s = interface->turnOnTorchWithStrengthLevel(torchStrength);
    if (!s.isOk()) {
        ALOGE("%s Unable to set torch mode strength %d : %s", __FUNCTION__, torchStrength,
                s.getMessage());
        return mapToStatusT(s);
    }
    mTorchStrengthLevel = torchStrength;
    return OK;
}

status_t AidlProviderInfo::AidlDeviceInfo3::getTorchStrengthLevel(int32_t *torchStrength) {
    if (torchStrength == nullptr) {
        return BAD_VALUE;
    }
    const std::shared_ptr<camera::device::ICameraDevice> interface = startDeviceInterface();
    if (interface == nullptr) {
        return DEAD_OBJECT;
    }

    ::ndk::ScopedAStatus status = interface->getTorchStrengthLevel(torchStrength);
    if (!status.isOk()) {
        ALOGE("%s: Couldn't get torch strength level: %s", __FUNCTION__, status.getMessage());
        return mapToStatusT(status);
    }
    return OK;
}

std::shared_ptr<aidl::android::hardware::camera::device::ICameraDevice>
AidlProviderInfo::AidlDeviceInfo3::startDeviceInterface() {
    Mutex::Autolock l(mDeviceAvailableLock);
    std::shared_ptr<camera::device::ICameraDevice> device;
    ATRACE_CALL();
    if (mSavedInterface == nullptr) {
        sp<AidlProviderInfo> parentProvider =
                static_cast<AidlProviderInfo *>(mParentProvider.promote().get());
        if (parentProvider != nullptr) {
            // Wait for lazy HALs to confirm device availability
            if (parentProvider->isExternalLazyHAL() && !mIsDeviceAvailable) {
                ALOGV("%s: Wait for external device to become available %s",
                      __FUNCTION__,
                      mId.c_str());

                auto res = mDeviceAvailableSignal.waitRelative(mDeviceAvailableLock,
                                                         kDeviceAvailableTimeout);
                if (res != OK) {
                    ALOGE("%s: Failed waiting for device to become available",
                          __FUNCTION__);
                    return nullptr;
                }
            }

            device = parentProvider->startDeviceInterface(mName);
        }
    } else {
        device = mSavedInterface;
    }
    return device;
}

status_t AidlProviderInfo::AidlDeviceInfo3::dumpState(int fd) {
    const std::shared_ptr<camera::device::ICameraDevice> interface = startDeviceInterface();
    if (interface == nullptr) {
        return DEAD_OBJECT;
    }
    const char *args = nullptr;
    auto ret = interface->dump(fd, &args, /*numArgs*/0);
    if (ret != OK) {
        return ret;
    }
    return OK;
}

status_t AidlProviderInfo::AidlDeviceInfo3::isSessionConfigurationSupported(
        const SessionConfiguration &configuration, bool overrideForPerfClass,
        camera3::metadataGetter getMetadata, bool *status) {

    camera::device::StreamConfiguration streamConfiguration;
    bool earlyExit = false;
    auto bRes = SessionConfigurationUtils::convertToHALStreamCombination(configuration,
            String8(mId.c_str()), mCameraCharacteristics, getMetadata, mPhysicalIds,
            streamConfiguration, overrideForPerfClass, &earlyExit);

    if (!bRes.isOk()) {
        return UNKNOWN_ERROR;
    }

    if (earlyExit) {
        *status = false;
        return OK;
    }

    const std::shared_ptr<camera::device::ICameraDevice> interface =
            startDeviceInterface();

    if (interface == nullptr) {
        return DEAD_OBJECT;
    }

    ::ndk::ScopedAStatus ret =
        interface->isStreamCombinationSupported(streamConfiguration, status);
    if (!ret.isOk()) {
        *status = false;
        ALOGE("%s: Unexpected binder error: %s", __FUNCTION__, ret.getMessage());
        return mapToStatusT(ret);
    }
    return OK;

}

status_t AidlProviderInfo::convertToAidlHALStreamCombinationAndCameraIdsLocked(
        const std::vector<CameraIdAndSessionConfiguration> &cameraIdsAndSessionConfigs,
        const std::set<std::string>& perfClassPrimaryCameraIds,
        int targetSdkVersion,
        std::vector<camera::provider::CameraIdAndStreamCombination>
                *halCameraIdsAndStreamCombinations,
        bool *earlyExit) {
    binder::Status bStatus = binder::Status::ok();
    std::vector<camera::provider::CameraIdAndStreamCombination> halCameraIdsAndStreamsV;
    bool shouldExit = false;
    status_t res = OK;
    for (auto &cameraIdAndSessionConfig : cameraIdsAndSessionConfigs) {
        const std::string& cameraId = cameraIdAndSessionConfig.mCameraId;
        camera::device::StreamConfiguration streamConfiguration;
        CameraMetadata deviceInfo;
        bool overrideForPerfClass =
                SessionConfigurationUtils::targetPerfClassPrimaryCamera(
                        perfClassPrimaryCameraIds, cameraId, targetSdkVersion);
        res = mManager->getCameraCharacteristicsLocked(cameraId, overrideForPerfClass, &deviceInfo,
                /*overrideToPortrait*/false);
        if (res != OK) {
            return res;
        }
        camera3::metadataGetter getMetadata =
                [this](const String8 &id, bool overrideForPerfClass) {
                    CameraMetadata physicalDeviceInfo;
                    mManager->getCameraCharacteristicsLocked(id.string(), overrideForPerfClass,
                                                   &physicalDeviceInfo,
                                                   /*overrideToPortrait*/false);
                    return physicalDeviceInfo;
                };
        std::vector<std::string> physicalCameraIds;
        mManager->isLogicalCameraLocked(cameraId, &physicalCameraIds);
        bStatus =
            SessionConfigurationUtils::convertToHALStreamCombination(
                    cameraIdAndSessionConfig.mSessionConfiguration,
                    String8(cameraId.c_str()), deviceInfo, getMetadata,
                    physicalCameraIds, streamConfiguration,
                    overrideForPerfClass, &shouldExit);
        if (!bStatus.isOk()) {
            ALOGE("%s: convertToHALStreamCombination failed", __FUNCTION__);
            return INVALID_OPERATION;
        }
        if (shouldExit) {
            *earlyExit = true;
            return OK;
        }
        camera::provider::CameraIdAndStreamCombination halCameraIdAndStream;
        halCameraIdAndStream.cameraId = cameraId;
        halCameraIdAndStream.streamConfiguration = streamConfiguration;
        halCameraIdsAndStreamsV.push_back(halCameraIdAndStream);
    }
    *halCameraIdsAndStreamCombinations = halCameraIdsAndStreamsV;
    return OK;
}

status_t AidlProviderInfo::isConcurrentSessionConfigurationSupported(
        const std::vector<CameraIdAndSessionConfiguration> &cameraIdsAndSessionConfigs,
        const std::set<std::string>& perfClassPrimaryCameraIds,
        int targetSdkVersion, bool *isSupported) {

      std::vector<camera::provider::CameraIdAndStreamCombination> halCameraIdsAndStreamCombinations;
      bool knowUnsupported = false;
      status_t res = convertToAidlHALStreamCombinationAndCameraIdsLocked(
              cameraIdsAndSessionConfigs, perfClassPrimaryCameraIds,
              targetSdkVersion, &halCameraIdsAndStreamCombinations, &knowUnsupported);
      if (res != OK) {
          ALOGE("%s unable to convert session configurations provided to HAL stream"
                "combinations", __FUNCTION__);
          return res;
      }
      if (knowUnsupported) {
          // We got to know the streams aren't valid before doing the HAL
          // call itself.
          *isSupported = false;
          return OK;
      }

      // Check if the provider is currently active - not going to start it up for this notification
      auto interface = mSavedInterface != nullptr ? mSavedInterface : mActiveInterface.lock();
      if (interface == nullptr) {
          // TODO: This might be some other problem
          return INVALID_OPERATION;
      }
      ::ndk::ScopedAStatus status = interface->isConcurrentStreamCombinationSupported(
              halCameraIdsAndStreamCombinations, isSupported);
      if (!status.isOk()) {
          *isSupported = false;
          ALOGE("%s: hal interface session configuration query failed", __FUNCTION__);
          return mapToStatusT(status);
      }

    return OK;
}

} //namespace android
