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

#define LOG_TAG "AidlCameraService"

#include "AidlCameraService.h"
#include <aidl/AidlCameraDeviceCallbacks.h>
#include <aidl/AidlCameraDeviceUser.h>
#include <aidl/AidlCameraServiceListener.h>
#include <aidl/AidlUtils.h>
#include <aidl/android/frameworks/cameraservice/common/CameraMetadataType.h>
#include <android-base/properties.h>
#include <android/binder_ibinder.h>
#include <android/binder_manager.h>
#include <binder/Status.h>
#include <hidl/HidlTransportSupport.h>
#include <utils/Utils.h>

namespace android::frameworks::cameraservice::service::implementation {

using ::android::frameworks::cameraservice::device::implementation::AidlCameraDeviceCallbacks;
using ::android::frameworks::cameraservice::device::implementation::AidlCameraDeviceUser;
using ::android::hardware::cameraservice::utils::conversion::aidl::areBindersEqual;
using ::android::hardware::cameraservice::utils::conversion::aidl::cloneToAidl;
using ::android::hardware::cameraservice::utils::conversion::aidl::convertToAidl;
using ::android::hardware::cameraservice::utils::conversion::aidl::filterVndkKeys;
using ::ndk::ScopedAStatus;

// VNDK classes
using SCameraMetadataType = ::aidl::android::frameworks::cameraservice::common::CameraMetadataType;
using SVendorTag = ::aidl::android::frameworks::cameraservice::common::VendorTag;
using SVendorTagSection = ::aidl::android::frameworks::cameraservice::common::VendorTagSection;
// NDK classes
using UICameraService = ::android::hardware::ICameraService;
using UStatus = ::android::binder::Status;

namespace {
inline ScopedAStatus fromSStatus(const SStatus& s) {
    return s == SStatus::NO_ERROR ? ScopedAStatus::ok()
                                  : ScopedAStatus::fromServiceSpecificError(
                                            static_cast<int32_t>(s));
}
inline ScopedAStatus fromUStatus(const UStatus& s) {
    return s.isOk() ? ScopedAStatus::ok() : fromSStatus(convertToAidl(s));
}
} // anonymous namespace

std::shared_ptr<AidlCameraService> kCameraService;

bool AidlCameraService::registerService(::android::CameraService* cameraService) {
    kCameraService = SharedRefBase::make<AidlCameraService>(cameraService);
    std::string serviceName = SBnCameraService::descriptor;
    serviceName += "/default";
    bool isDeclared = AServiceManager_isDeclared(serviceName.c_str());
    if (!isDeclared) {
        ALOGI("%s: AIDL vndk not declared.", __FUNCTION__);
        return false;
    }

    binder_exception_t registered = AServiceManager_addService(
            kCameraService->asBinder().get(), serviceName.c_str());
    ALOGE_IF(registered != EX_NONE,
             "%s: AIDL VNDK declared, but failed to register service: %d",
             __FUNCTION__, registered);
    return registered == EX_NONE;
}

AidlCameraService::AidlCameraService(::android::CameraService* cameraService):
      mCameraService(cameraService) {
    mVndkVersion = getVNDKVersionFromProp(__ANDROID_API_FUTURE__);
}
ScopedAStatus AidlCameraService::getCameraCharacteristics(const std::string& in_cameraId,
                                                          SCameraMetadata* _aidl_return) {
    if (_aidl_return == nullptr) { return fromSStatus(SStatus::ILLEGAL_ARGUMENT); }

    ::android::CameraMetadata cameraMetadata;
    UStatus ret = mCameraService->getCameraCharacteristics(in_cameraId,
                                                           mVndkVersion,
                                                           /* overrideToPortrait= */ false,
                                                           &cameraMetadata);
    if (!ret.isOk()) {
        if (ret.exceptionCode() != EX_SERVICE_SPECIFIC) {
            ALOGE("%s: Transaction error when getting camera characteristics"
                  " from camera service: %d.",
                  __FUNCTION__ , ret.exceptionCode());
            return fromUStatus(ret);
        }
        switch (ret.serviceSpecificErrorCode()) {
            case UICameraService::ERROR_ILLEGAL_ARGUMENT:
                ALOGE("%s: Camera ID %s does not exist!", __FUNCTION__, in_cameraId.c_str());
                return fromSStatus(SStatus::ILLEGAL_ARGUMENT);
            default:
                ALOGE("Get camera characteristics from camera service failed: %s",
                      ret.toString8().c_str());
                return fromUStatus(ret);
        }
    }

    if (filterVndkKeys(mVndkVersion, cameraMetadata) != OK) {
         ALOGE("%s: Unable to filter vndk metadata keys for version %d",
              __FUNCTION__, mVndkVersion);
         return fromSStatus(SStatus::UNKNOWN_ERROR);
    }

    const camera_metadata_t* rawMetadata = cameraMetadata.getAndLock();
    cloneToAidl(rawMetadata, _aidl_return);
    cameraMetadata.unlock(rawMetadata);

    return ScopedAStatus::ok();
}
ndk::ScopedAStatus AidlCameraService::connectDevice(
        const std::shared_ptr<SICameraDeviceCallback>& in_callback,
        const std::string& in_cameraId,
        std::shared_ptr<SICameraDeviceUser>* _aidl_return) {
    // Here, we first get NDK ICameraDeviceUser from mCameraService, then save
    // that interface in the newly created AidlCameraDeviceUser impl class.
    if (mCameraService == nullptr) {
        return fromSStatus(SStatus::UNKNOWN_ERROR);
    }
    sp<hardware::camera2::ICameraDeviceUser> unstableDevice = nullptr;
    // Create a hardware::camera2::ICameraDeviceCallback object which internally
    // calls callback functions passed through hCallback.
    sp<AidlCameraDeviceCallbacks> hybridCallbacks = new AidlCameraDeviceCallbacks(in_callback);
    if (!hybridCallbacks->initializeLooper(mVndkVersion)) {
        ALOGE("Unable to handle callbacks on device, cannot connect");
        return fromSStatus(SStatus::UNKNOWN_ERROR);
    }
    sp<hardware::camera2::ICameraDeviceCallbacks> callbacks = hybridCallbacks;
    binder::Status serviceRet = mCameraService->connectDevice(
            callbacks,
            in_cameraId,
            std::string(),
            /* clientFeatureId= */{},
            hardware::ICameraService::USE_CALLING_UID,
            /* scoreOffset= */ 0,
            /* targetSdkVersion= */ __ANDROID_API_FUTURE__,
            /* overrideToPortrait= */ false,
            &unstableDevice);
    if (!serviceRet.isOk()) {
        ALOGE("%s: Unable to connect to camera device: %s", __FUNCTION__,
              serviceRet.toString8().c_str());
        return fromUStatus(serviceRet);
    }

    // Now we create a AidlCameraDeviceUser class, store the unstableDevice in it,
    // and return that back. All calls on that interface will be forwarded to
    // the NDK AIDL interface.
    std::shared_ptr<AidlCameraDeviceUser> stableDevice =
            ndk::SharedRefBase::make<AidlCameraDeviceUser>(unstableDevice);
    if (!stableDevice->initStatus()) {
        ALOGE("%s: Unable to initialize camera device AIDL wrapper", __FUNCTION__);
        return fromSStatus(SStatus::UNKNOWN_ERROR);
    }
    hybridCallbacks->setCaptureResultMetadataQueue(
            stableDevice->getCaptureResultMetadataQueue());
    *_aidl_return = stableDevice;
    return ScopedAStatus::ok();
}
void AidlCameraService::addToListenerCacheLocked(
        std::shared_ptr<SICameraServiceListener> stableCsListener,
        sp<UICameraServiceListener> csListener) {
    mListeners.emplace_back(std::make_pair(stableCsListener, csListener));
}
sp<UICameraServiceListener> AidlCameraService::searchListenerCacheLocked(
        const std::shared_ptr<SICameraServiceListener>& listener, bool removeIfFound) {
    // Go through the mListeners list and compare the listener with the VNDK AIDL
    // listener registered.
    if (listener == nullptr) {
        return nullptr;
    }

    auto it = mListeners.begin();
    sp<UICameraServiceListener> csListener = nullptr;
    for (;it != mListeners.end(); it++) {
        if (areBindersEqual(listener->asBinder(), it->first->asBinder())) {
            break;
        }
    }
    if (it != mListeners.end()) {
        csListener = it->second;
        if (removeIfFound) {
            mListeners.erase(it);
        }
    }
    return csListener;
}
ndk::ScopedAStatus AidlCameraService::addListener(
        const std::shared_ptr<SICameraServiceListener>& in_listener,
        std::vector<SCameraStatusAndId>* _aidl_return) {
    std::vector<hardware::CameraStatus> cameraStatusAndIds{};
    SStatus status = addListenerInternal(
            in_listener, &cameraStatusAndIds);
    if (status != SStatus::NO_ERROR) {
        return fromSStatus(status);
    }

    // Convert cameraStatusAndIds to VNDK AIDL
    convertToAidl(cameraStatusAndIds, _aidl_return);
    return ScopedAStatus::ok();
}
SStatus AidlCameraService::addListenerInternal(
        const std::shared_ptr<SICameraServiceListener>& listener,
        std::vector<hardware::CameraStatus>* cameraStatusAndIds) {
    if (mCameraService == nullptr) {
        return SStatus::UNKNOWN_ERROR;
    }
    if (listener == nullptr || cameraStatusAndIds == nullptr) {
        ALOGE("%s listener and cameraStatusAndIds must not be NULL", __FUNCTION__);
        return SStatus::ILLEGAL_ARGUMENT;
    }
    sp<UICameraServiceListener> csListener = nullptr;
    // Check the cache for previously registered callbacks
    {
        Mutex::Autolock l(mListenerListLock);
        csListener = searchListenerCacheLocked(listener);
        if (csListener == nullptr) {
            // Wrap a listener with AidlCameraServiceListener and pass it to
            // CameraService.
            csListener = sp<AidlCameraServiceListener>::make(listener);
            // Add to cache
            addToListenerCacheLocked(listener, csListener);
        } else {
            ALOGE("%s: Trying to add a listener %p already registered",
                  __FUNCTION__, listener.get());
            return SStatus::ILLEGAL_ARGUMENT;
        }
    }
    binder::Status serviceRet =
            mCameraService->addListenerHelper(csListener, cameraStatusAndIds, true);
    if (!serviceRet.isOk()) {
        ALOGE("%s: Unable to add camera device status listener", __FUNCTION__);
        return convertToAidl(serviceRet);
    }

    cameraStatusAndIds->erase(std::remove_if(cameraStatusAndIds->begin(),
                                             cameraStatusAndIds->end(),
            [this](const hardware::CameraStatus& s) {
                bool supportsHAL3 = false;
                binder::Status sRet =
                            mCameraService->supportsCameraApi(s.cameraId,
                                    UICameraService::API_VERSION_2, &supportsHAL3);
                return !sRet.isOk() || !supportsHAL3;
            }), cameraStatusAndIds->end());

    return SStatus::NO_ERROR;
}
ndk::ScopedAStatus AidlCameraService::removeListener(
        const std::shared_ptr<SICameraServiceListener>& in_listener) {
    if (in_listener == nullptr) {
        ALOGE("%s listener must not be NULL", __FUNCTION__);
        return fromSStatus(SStatus::ILLEGAL_ARGUMENT);
    }
    sp<UICameraServiceListener> csListener = nullptr;
    {
        Mutex::Autolock l(mListenerListLock);
        csListener = searchListenerCacheLocked(in_listener, /*removeIfFound*/true);
    }
    if (csListener != nullptr) {
          mCameraService->removeListener(csListener);
    } else {
        ALOGE("%s Removing unregistered listener %p", __FUNCTION__, in_listener.get());
        return fromSStatus(SStatus::ILLEGAL_ARGUMENT);
    }
    return ScopedAStatus::ok();
}
ndk::ScopedAStatus AidlCameraService::getCameraVendorTagSections(
        std::vector<SProviderIdAndVendorTagSections>* _aidl_return) {
    sp<VendorTagDescriptorCache> gCache = VendorTagDescriptorCache::getGlobalVendorTagCache();
    if (gCache == nullptr) {
        return fromSStatus(SStatus::UNKNOWN_ERROR);
    }

    const std::unordered_map<metadata_vendor_id_t, sp<android::VendorTagDescriptor>>
            &vendorIdsAndTagDescs = gCache->getVendorIdsAndTagDescriptors();
    if (vendorIdsAndTagDescs.empty()) {
        return fromSStatus(SStatus::UNKNOWN_ERROR);
    }

    std::vector<SProviderIdAndVendorTagSections>& tagIdAndVendorTagSections = *_aidl_return;
    tagIdAndVendorTagSections.resize(vendorIdsAndTagDescs.size());
    size_t j = 0;
    for (auto &vendorIdAndTagDescs : vendorIdsAndTagDescs) {
        std::vector<SVendorTagSection> vendorTagSections;
        sp<VendorTagDescriptor> desc = vendorIdAndTagDescs.second;
        const SortedVector<String8>* sectionNames = desc->getAllSectionNames();
        size_t numSections = sectionNames->size();
        std::vector<std::vector<SVendorTag>> tagsBySection(numSections);
        int tagCount = desc->getTagCount();
        if (tagCount <= 0) {
            continue;
        }
        std::vector<uint32_t> tags(tagCount);
        desc->getTagArray(tags.data());
        for (int i = 0; i < tagCount; i++) {
            SVendorTag vt;
            vt.tagId = tags[i];
            vt.tagName = desc->getTagName(tags[i]);
            vt.tagType = (SCameraMetadataType) desc->getTagType(tags[i]);
            ssize_t sectionIdx = desc->getSectionIndex(tags[i]);
            tagsBySection[sectionIdx].push_back(vt);
        }
        vendorTagSections.resize(numSections);
        for (size_t s = 0; s < numSections; s++) {
            vendorTagSections[s].sectionName = (*sectionNames)[s].c_str();
            vendorTagSections[s].tags = tagsBySection[s];
        }
        SProviderIdAndVendorTagSections & prvdrIdAndVendorTagSection =
                tagIdAndVendorTagSections[j];
        prvdrIdAndVendorTagSection.providerId = vendorIdAndTagDescs.first;
        prvdrIdAndVendorTagSection.vendorTagSections = std::move(vendorTagSections);
        j++;
    }
    return ScopedAStatus::ok();
}

} // namespace android::frameworks::cameraservice::service::implementation
