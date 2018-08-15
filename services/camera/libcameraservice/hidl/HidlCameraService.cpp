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

#include <hidl/Convert.h>

#include <hidl/HidlCameraService.h>

#include <hidl/HidlTransportSupport.h>

namespace android {
namespace frameworks {
namespace cameraservice {
namespace service {
namespace V2_0 {
namespace implementation {

using frameworks::cameraservice::service::V2_0::implementation::HidlCameraService;
using hardware::hidl_vec;
using hardware::cameraservice::utils::conversion::convertToHidl;
using hardware::cameraservice::utils::conversion::B2HStatus;
using hardware::Void;

using HCameraMetadataType = android::frameworks::cameraservice::common::V2_0::CameraMetadataType;
using HVendorTag = android::frameworks::cameraservice::common::V2_0::VendorTag;
using HVendorTagSection = android::frameworks::cameraservice::common::V2_0::VendorTagSection;

sp<HidlCameraService> gHidlCameraService;

sp<HidlCameraService> HidlCameraService::getInstance(android::CameraService *cs) {
    gHidlCameraService = new HidlCameraService(cs);
    return gHidlCameraService;
}

Return<void>
HidlCameraService::getCameraCharacteristics(const hidl_string& cameraId,
                                            getCameraCharacteristics_cb _hidl_cb) {
    android::CameraMetadata cameraMetadata;
    HStatus status = HStatus::NO_ERROR;
    binder::Status serviceRet =
        mAidlICameraService->getCameraCharacteristics(String16(cameraId.c_str()), &cameraMetadata);
    HCameraMetadata hidlMetadata;
    if (!serviceRet.isOk()) {
        switch(serviceRet.serviceSpecificErrorCode()) {
            // No ERROR_CAMERA_DISCONNECTED since we're in the same process.
            case hardware::ICameraService::ERROR_ILLEGAL_ARGUMENT:
                ALOGE("%s: Camera ID %s does not exist!", __FUNCTION__, cameraId.c_str());
                status = HStatus::ILLEGAL_ARGUMENT;
                break;
            default:
                ALOGE("Get camera characteristics from camera service failed: %s",
                      serviceRet.toString8().string());
                status = B2HStatus(serviceRet);
          }
        _hidl_cb(status, hidlMetadata);
        return Void();
    }
    const camera_metadata_t *rawMetadata = cameraMetadata.getAndLock();
    convertToHidl(rawMetadata, &hidlMetadata);
    _hidl_cb(status, hidlMetadata);
    cameraMetadata.unlock(rawMetadata);
    return Void();
}

Return<void> HidlCameraService::connectDevice(const sp<HCameraDeviceCallback>& hCallback,
                                              const hidl_string& cameraId,
                                              connectDevice_cb _hidl_cb) {
    // To silence Wunused-parameter.
    (void)hCallback;
    (void)cameraId;
    (void)_hidl_cb;

    return Void();
}

Return<void> HidlCameraService::addListener(const sp<HCameraServiceListener>& hCsListener,
                                            addListener_cb _hidl_cb) {
    // To silence Wunused-parameter.
    (void)hCsListener;
    (void)_hidl_cb;

    return Void();
}

Return<HStatus> HidlCameraService::removeListener(const sp<HCameraServiceListener>& hCsListener) {
    if (hCsListener == nullptr) {
        ALOGE("%s listener must not be NULL", __FUNCTION__);
        return HStatus::ILLEGAL_ARGUMENT;
    }
    return HStatus::NO_ERROR;
}

Return<void> HidlCameraService::getCameraVendorTagSections(getCameraVendorTagSections_cb _hidl_cb) {
    hidl_vec<HVendorTagSection> hVendorTagSections;
    // TODO: Could this be just created on the stack since we don't set it to
    //       global cache or anything ?
    HStatus hStatus = HStatus::NO_ERROR;
    sp<VendorTagDescriptor> desc = new VendorTagDescriptor();
    binder::Status serviceRet = mAidlICameraService->getCameraVendorTagDescriptor(desc.get());

    if (!serviceRet.isOk()) {
        ALOGE("%s: Failed to get VendorTagDescriptor", __FUNCTION__);
        _hidl_cb(B2HStatus(serviceRet), hVendorTagSections);
        return Void();
    }

    const SortedVector<String8>* sectionNames = desc->getAllSectionNames();
    size_t numSections = sectionNames->size();
    std::vector<std::vector<HVendorTag>> tagsBySection(numSections);
    int tagCount = desc->getTagCount();
    std::vector<uint32_t> tags(tagCount);
    desc->getTagArray(tags.data());
    for (int i = 0; i < tagCount; i++) {
        HVendorTag vt;
        vt.tagId = tags[i];
        vt.tagName = desc->getTagName(tags[i]);
        vt.tagType = (HCameraMetadataType) desc->getTagType(tags[i]);
        ssize_t sectionIdx = desc->getSectionIndex(tags[i]);
        tagsBySection[sectionIdx].push_back(vt);
    }
    hVendorTagSections.resize(numSections);
    for (size_t s = 0; s < numSections; s++) {
        hVendorTagSections[s].sectionName = (*sectionNames)[s].string();
        hVendorTagSections[s].tags = tagsBySection[s];
    }
    _hidl_cb(hStatus, hVendorTagSections);
    return Void();
}

} // implementation
} // V2_0
} // service
} // cameraservice
} // frameworks
} // android

