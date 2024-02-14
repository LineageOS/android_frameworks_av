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

//#define LOG_NDEBUG 0
#define LOG_TAG "ACameraManagerVendor"

#include "ACameraMetadata.h"
#include "ndk_vendor/impl/ACameraDevice.h"
#include "ndk_vendor/impl/ACameraManager.h"
#include "utils.h"

#include <CameraMetadata.h>
#include <VendorTagDescriptor.h>
#include <android/binder_manager.h>
#include <android/binder_process.h>
#include <camera_metadata_hidden.h>
#include <cutils/properties.h>
#include <memory>
#include <utils/Vector.h>

using namespace android::acam;

namespace android {
namespace acam {

using ::aidl::android::frameworks::cameraservice::common::ProviderIdAndVendorTagSections;
using ::android::hardware::camera::common::V1_0::helper::VendorTagDescriptor;
using ::android::hardware::camera::common::V1_0::helper::VendorTagDescriptorCache;
using ::ndk::ScopedAStatus;

// Static member definitions
const char* CameraManagerGlobal::kCameraIdKey   = "CameraId";
const char* CameraManagerGlobal::kPhysicalCameraIdKey   = "PhysicalCameraId";
const char* CameraManagerGlobal::kCallbackFpKey = "CallbackFp";
const char* CameraManagerGlobal::kContextKey    = "CallbackContext";
const nsecs_t CameraManagerGlobal::kCallbackDrainTimeout = 5000000; // 5 ms
Mutex                CameraManagerGlobal::sLock;
std::weak_ptr<CameraManagerGlobal> CameraManagerGlobal::sInstance =
        std::weak_ptr<CameraManagerGlobal>();

/**
 * The vendor tag descriptor class that takes AIDL vendor tag information as
 * input. Not part of vendor available VendorTagDescriptor class because that class is used by
 * default HAL implementation code as well.
 *
 * This is a class instead of a free-standing function because VendorTagDescriptor has some
 * protected fields that need to be initialized during conversion.
 */
class AidlVendorTagDescriptor : public VendorTagDescriptor {
public:
    /**
     * Create a VendorTagDescriptor object from the AIDL VendorTagSection
     * vector.
     *
     * Returns OK on success, or a negative error code.
     */
    static status_t createDescriptorFromAidl(const std::vector<VendorTagSection>& vts,
                                             /*out*/ sp<VendorTagDescriptor> *descriptor);
};

status_t AidlVendorTagDescriptor::createDescriptorFromAidl(const std::vector<VendorTagSection>& vts,
                                                           sp<VendorTagDescriptor>* descriptor){
    size_t tagCount = 0;

    for (size_t s = 0; s < vts.size(); s++) {
        tagCount += vts[s].tags.size();
    }

    if (tagCount < 0 || tagCount > INT32_MAX) {
        ALOGE("%s: tag count %zu from vendor tag sections is invalid.", __FUNCTION__, tagCount);
        return BAD_VALUE;
    }

    std::vector<int64_t> tagArray;
    tagArray.resize(tagCount);

    sp<AidlVendorTagDescriptor> desc = new AidlVendorTagDescriptor();
    desc->mTagCount = tagCount;

    std::map<int64_t, std::string> tagToSectionMap;

    int idx = 0;
    for (size_t s = 0; s < vts.size(); s++) {
        const VendorTagSection& section = vts[s];
        const char *sectionName = section.sectionName.c_str();
        if (sectionName == nullptr) {
            ALOGE("%s: no section name defined for vendor tag section %zu.", __FUNCTION__, s);
            return BAD_VALUE;
        }
        String8 sectionString(sectionName);
        desc->mSections.add(sectionString);

        for (size_t j = 0; j < section.tags.size(); j++) {
            uint32_t tag = section.tags[j].tagId;
            if (tag < CAMERA_METADATA_VENDOR_TAG_BOUNDARY) {
                ALOGE("%s: vendor tag %d not in vendor tag section.", __FUNCTION__, tag);
                return BAD_VALUE;
            }

            tagArray[idx++] = section.tags[j].tagId;

            const char *tagName = section.tags[j].tagName.c_str();
            if (tagName == nullptr) {
                ALOGE("%s: no tag name defined for vendor tag %d.", __FUNCTION__, tag);
                return BAD_VALUE;
            }
            desc->mTagToNameMap.add(tag, String8(tagName));
            tagToSectionMap.insert({tag, section.sectionName});

            int tagType = (int) section.tags[j].tagType;
            if (tagType < 0 || tagType >= NUM_TYPES) {
                ALOGE("%s: tag type %d from vendor ops does not exist.", __FUNCTION__, tagType);
                return BAD_VALUE;
            }
            desc->mTagToTypeMap.emplace(tag, tagType);
        }
    }

    for (size_t i = 0; i < tagArray.size(); ++i) {
        uint32_t tag = tagArray[i];
        auto itr = tagToSectionMap.find(tag);
        if (itr == tagToSectionMap.end()) {
            ALOGE("%s: Couldn't find previously added tag in map.", __FUNCTION__);
            return UNKNOWN_ERROR;
        }
        String8 sectionString = String8(itr->second.c_str());
        // Set up tag to section index map
        ssize_t index = desc->mSections.indexOf(sectionString);
        LOG_ALWAYS_FATAL_IF(index < 0, "index %zd must be non-negative", index);
        desc->mTagToSectionMap.add(tag, static_cast<uint32_t>(index));

        // Set up reverse mapping
        ssize_t reverseIndex = -1;
        if ((reverseIndex = desc->mReverseMapping.indexOfKey(sectionString)) < 0) {
            KeyedVector<String8, uint32_t>* nameMapper = new KeyedVector<String8, uint32_t>();
            reverseIndex = desc->mReverseMapping.add(sectionString, nameMapper);
        }
        desc->mReverseMapping[reverseIndex]->add(desc->mTagToNameMap.valueFor(tag), tag);
    }

    *descriptor = std::move(desc);
    return OK;
}

std::shared_ptr<CameraManagerGlobal> CameraManagerGlobal::getInstance() {
    Mutex::Autolock _l(sLock);
    std::shared_ptr<CameraManagerGlobal> instance = sInstance.lock();
    if (instance == nullptr) {
        instance = std::make_shared<CameraManagerGlobal>();
        sInstance = instance;
    }
    return instance;
}

CameraManagerGlobal::~CameraManagerGlobal() {
    Mutex::Autolock _sl(sLock);
    Mutex::Autolock _l(mLock);
    if (mCameraService != nullptr) {
        AIBinder_unlinkToDeath(mCameraService->asBinder().get(),
                               mDeathRecipient.get(), this);
        auto stat = mCameraService->removeListener(mCameraServiceListener);
        if (!stat.isOk()) {
            ALOGE("Failed to remove listener to camera service %d:%d", stat.getExceptionCode(),
                  stat.getServiceSpecificError());
        }
    }

    if (mCbLooper != nullptr) {
        mCbLooper->unregisterHandler(mHandler->id());
        mCbLooper->stop();
    }
    mCbLooper.clear();
    mHandler.clear();
    mCameraServiceListener.reset();
    mCameraService.reset();
}

static bool isCameraServiceDisabled() {
    char value[PROPERTY_VALUE_MAX];
    property_get("config.disable_cameraservice", value, "0");
    return (strncmp(value, "0", 2) != 0 && strncasecmp(value, "false", 6) != 0);
}

bool CameraManagerGlobal::setupVendorTags() {
    sp<VendorTagDescriptorCache> tagCache = new VendorTagDescriptorCache();
    Status status = Status::NO_ERROR;
    std::vector<ProviderIdAndVendorTagSections> providerIdsAndVts;
    ScopedAStatus remoteRet = mCameraService->getCameraVendorTagSections(&providerIdsAndVts);

    if (!remoteRet.isOk()) {
        if (remoteRet.getExceptionCode() == EX_SERVICE_SPECIFIC) {
            Status errStatus = static_cast<Status>(remoteRet.getServiceSpecificError());
            ALOGE("%s: Failed to retrieve VendorTagSections %s",
                __FUNCTION__, toString(status).c_str());
        } else {
            ALOGE("%s: Binder error when retrieving VendorTagSections: %d", __FUNCTION__,
                remoteRet.getExceptionCode());
        }
        return false;
    }

    // Convert each providers VendorTagSections into a VendorTagDescriptor and
    // add it to the cache
    for (auto &providerIdAndVts : providerIdsAndVts) {
        sp<VendorTagDescriptor> vendorTagDescriptor;
        status_t ret = AidlVendorTagDescriptor::createDescriptorFromAidl(
                providerIdAndVts.vendorTagSections, &vendorTagDescriptor);
        if (ret != OK) {
            ALOGE("Failed to convert from Aidl: VendorTagDescriptor: %d", ret);
            return false;
        }
        tagCache->addVendorDescriptor(providerIdAndVts.providerId, vendorTagDescriptor);
    }
    VendorTagDescriptorCache::setAsGlobalVendorTagCache(tagCache);
    return true;
}

std::shared_ptr<ICameraService> CameraManagerGlobal::getCameraService() {
    Mutex::Autolock _l(mLock);

    if (mCameraService != nullptr) {
        // Camera service already set up. Return existing value.
        return mCameraService;
    }

    if (isCameraServiceDisabled()) {
        // Camera service is disabled. return nullptr.
        return mCameraService;
    }

    std::string serviceName = ICameraService::descriptor;
    serviceName += "/default";

    bool isDeclared = AServiceManager_isDeclared(serviceName.c_str());
    if (!isDeclared) {
        ALOGE("%s: No ICameraService instance declared: %s", __FUNCTION__, serviceName.c_str());
        return nullptr;
    }

    // Before doing any more make sure there is a binder threadpool alive
    // This is a no-op if the binder threadpool was already started by this process.
    ABinderProcess_startThreadPool();

    std::shared_ptr<ICameraService> cameraService =
            ICameraService::fromBinder(ndk::SpAIBinder(
                    AServiceManager_waitForService(serviceName.c_str())));
    if (cameraService == nullptr) {
        ALOGE("%s: Could not get ICameraService instance.", __FUNCTION__);
        return nullptr;
    }

    if (mDeathRecipient.get() == nullptr) {
        mDeathRecipient = ndk::ScopedAIBinder_DeathRecipient(
                AIBinder_DeathRecipient_new(CameraManagerGlobal::binderDeathCallback));
    }
    AIBinder_linkToDeath(cameraService->asBinder().get(),
                         mDeathRecipient.get(), /*cookie=*/ this);

    mCameraService = cameraService;

    // Setup looper thread to perform availability callbacks
    if (mCbLooper == nullptr) {
        mCbLooper = new ALooper;
        mCbLooper->setName("C2N-mgr-looper");
        status_t err = mCbLooper->start(
                /*runOnCallingThread*/false,
                /*canCallJava*/       true,
                PRIORITY_DEFAULT);
        if (err != OK) {
            ALOGE("%s: Unable to start camera service listener looper: %s (%d)",
                    __FUNCTION__, strerror(-err), err);
            mCbLooper.clear();
            return nullptr;
        }
        if (mHandler == nullptr) {
            mHandler = new CallbackHandler(weak_from_this());
        }
        mCbLooper->registerHandler(mHandler);
    }

    // register ICameraServiceListener
    if (mCameraServiceListener == nullptr) {
        mCameraServiceListener = ndk::SharedRefBase::make<CameraServiceListener>(weak_from_this());
    }

    std::vector<CameraStatusAndId> cameraStatuses;
    Status status = Status::NO_ERROR;
    ScopedAStatus remoteRet = mCameraService->addListener(mCameraServiceListener,
                                                          &cameraStatuses);

    if (!remoteRet.isOk()) {
        if (remoteRet.getExceptionCode() == EX_SERVICE_SPECIFIC) {
            Status errStatus = static_cast<Status>(remoteRet.getServiceSpecificError());
            ALOGE("%s: Failed to add listener to camera service: %s", __FUNCTION__,
                toString(errStatus).c_str());
        } else {
            ALOGE("%s: Transaction failed when adding listener to camera service: %d",
                __FUNCTION__, remoteRet.getExceptionCode());
        }
    }

    // Setup vendor tags
    if (!setupVendorTags()) {
        ALOGE("Unable to set up vendor tags");
        return nullptr;
    }

    for (auto& csi: cameraStatuses){
        onStatusChangedLocked(csi.deviceStatus, csi.cameraId);

        for (auto& unavailablePhysicalId : csi.unavailPhysicalCameraIds) {
            onStatusChangedLocked(CameraDeviceStatus::STATUS_NOT_PRESENT,
                                  csi.cameraId, unavailablePhysicalId);
        }
    }
    return mCameraService;
}

void CameraManagerGlobal::binderDeathCallback(void* /*cookie*/) {
    AutoMutex _l(sLock);

    ALOGE("Camera service binderDied!");
    std::shared_ptr<CameraManagerGlobal> instance = sInstance.lock();
    if (instance == nullptr) {
        return;
    }

    // Remove cameraService from the static instance
    AutoMutex lock(instance->mLock);
    for (auto& pair : instance->mDeviceStatusMap) {
        const auto &cameraId = pair.first;
        const auto &deviceStatus = pair.second.getStatus();
        instance->onStatusChangedLocked(deviceStatus, cameraId);
    }
    instance->mCameraService.reset();
    // TODO: consider adding re-connect call here?
}

void CameraManagerGlobal::registerAvailabilityCallback(
        const ACameraManager_AvailabilityCallbacks *callback) {
    return registerAvailCallback<ACameraManager_AvailabilityCallbacks>(callback);
}

void CameraManagerGlobal::unregisterAvailabilityCallback(
        const ACameraManager_AvailabilityCallbacks *callback) {
    Mutex::Autolock _l(mLock);
    drainPendingCallbacksLocked();
    Callback cb(callback);
    mCallbacks.erase(cb);
}

void CameraManagerGlobal::registerExtendedAvailabilityCallback(
        const ACameraManager_ExtendedAvailabilityCallbacks *callback) {
    return registerAvailCallback<ACameraManager_ExtendedAvailabilityCallbacks>(callback);
}

void CameraManagerGlobal::unregisterExtendedAvailabilityCallback(
        const ACameraManager_ExtendedAvailabilityCallbacks *callback) {
    Mutex::Autolock _l(mLock);
    drainPendingCallbacksLocked();
    Callback cb(callback);
    mCallbacks.erase(cb);
}

void CameraManagerGlobal::onCallbackCalled() {
    Mutex::Autolock _l(mLock);
    if (mPendingCallbackCnt > 0) {
        mPendingCallbackCnt--;
    }
    mCallbacksCond.signal();
}

void CameraManagerGlobal::drainPendingCallbacksLocked() {
    while (mPendingCallbackCnt > 0) {
        auto res = mCallbacksCond.waitRelative(mLock, kCallbackDrainTimeout);
        if (res != NO_ERROR) {
            ALOGE("%s: Error waiting to drain callbacks: %s(%d)",
                    __FUNCTION__, strerror(-res), res);
            break;
        }
    }
}

template <class T>
void CameraManagerGlobal::registerAvailCallback(const T *callback) {
    getCameraService();
    Mutex::Autolock _l(mLock);
    Callback cb(callback);
    auto res = mCallbacks.insert(cb);
    if (!res.second) {
        ALOGE("%s: Failed to register callback. Couldn't insert in map.", __FUNCTION__);
        return;
    }
    // Send initial callbacks if callback is newly registered
    for (auto& pair : mDeviceStatusMap) {
        const std::string& cameraId = pair.first;
        CameraDeviceStatus status = pair.second.getStatus();

        {
            // Camera available/unavailable callback
            sp<AMessage> msg = new AMessage(kWhatSendSingleCallback, mHandler);
            ACameraManager_AvailabilityCallback cbFunc = isStatusAvailable(status) ?
                                                         cb.mAvailable : cb.mUnavailable;
            msg->setPointer(kCallbackFpKey, (void *) cbFunc);
            msg->setPointer(kContextKey, cb.mContext);
            msg->setString(kCameraIdKey, AString(cameraId.c_str()));
            mPendingCallbackCnt++;
            msg->post();
        }

        // Physical camera unavailable callback
        std::set<std::string> unavailPhysicalIds = pair.second.getUnavailablePhysicalIds();
        for (const auto& physicalCameraId : unavailPhysicalIds) {
            sp<AMessage> msg = new AMessage(kWhatSendSinglePhysicalCameraCallback, mHandler);
            ACameraManager_PhysicalCameraAvailabilityCallback cbFunc =
                    cb.mPhysicalCamUnavailable;
            msg->setPointer(kCallbackFpKey, (void *) cbFunc);
            msg->setPointer(kContextKey, cb.mContext);
            msg->setString(kCameraIdKey, AString(cameraId.c_str()));
            msg->setString(kPhysicalCameraIdKey, AString(physicalCameraId.c_str()));
            mPendingCallbackCnt++;
            msg->post();
        }
    }
}

void CameraManagerGlobal::getCameraIdList(std::vector<std::string>* cameraIds) {
    // Ensure that we have initialized/refreshed the list of available devices
    auto cs = getCameraService();
    Mutex::Autolock _l(mLock);

    for(auto& deviceStatus : mDeviceStatusMap) {
        CameraDeviceStatus status = deviceStatus.second.getStatus();
        if (status == CameraDeviceStatus::STATUS_NOT_PRESENT ||
                status == CameraDeviceStatus::STATUS_ENUMERATING) {
            continue;
        }
        cameraIds->push_back(deviceStatus.first);
    }
}

bool CameraManagerGlobal::validStatus(CameraDeviceStatus status) {
    switch (status) {
        case CameraDeviceStatus::STATUS_NOT_PRESENT:
        case CameraDeviceStatus::STATUS_PRESENT:
        case CameraDeviceStatus::STATUS_ENUMERATING:
        case CameraDeviceStatus::STATUS_NOT_AVAILABLE:
            return true;
        default:
            return false;
    }
}

bool CameraManagerGlobal::isStatusAvailable(CameraDeviceStatus status) {
    switch (status) {
        case CameraDeviceStatus::STATUS_PRESENT:
            return true;
        default:
            return false;
    }
}

void CameraManagerGlobal::CallbackHandler::onMessageReceived(
      const sp<AMessage> &msg) {
    onMessageReceivedInternal(msg);
    if (msg->what() == kWhatSendSingleCallback ||
            msg->what() == kWhatSendSinglePhysicalCameraCallback) {
        notifyParent();
    }
}

void CameraManagerGlobal::CallbackHandler::onMessageReceivedInternal(
        const sp<AMessage> &msg) {
    switch (msg->what()) {
        case kWhatSendSingleCallback:
        {
            ACameraManager_AvailabilityCallback cb;
            void* context;
            AString cameraId;
            bool found = msg->findPointer(kCallbackFpKey, (void**) &cb);
            if (!found) {
                ALOGE("%s: Cannot find camera callback fp!", __FUNCTION__);
                return;
            }
            found = msg->findPointer(kContextKey, &context);
            if (!found) {
                ALOGE("%s: Cannot find callback context!", __FUNCTION__);
                return;
            }
            found = msg->findString(kCameraIdKey, &cameraId);
            if (!found) {
                ALOGE("%s: Cannot find camera ID!", __FUNCTION__);
                return;
            }
            (*cb)(context, cameraId.c_str());
            break;
        }
        case kWhatSendSinglePhysicalCameraCallback:
        {
            ACameraManager_PhysicalCameraAvailabilityCallback cb;
            void* context;
            AString cameraId;
            AString physicalCameraId;
            bool found = msg->findPointer(kCallbackFpKey, (void**) &cb);
            if (!found) {
                ALOGE("%s: Cannot find camera callback fp!", __FUNCTION__);
                return;
            }
            if (cb == nullptr) {
                // Physical camera callback is null
                return;
            }
            found = msg->findPointer(kContextKey, &context);
            if (!found) {
                ALOGE("%s: Cannot find callback context!", __FUNCTION__);
                return;
            }
            found = msg->findString(kCameraIdKey, &cameraId);
            if (!found) {
                ALOGE("%s: Cannot find camera ID!", __FUNCTION__);
                return;
            }
            found = msg->findString(kPhysicalCameraIdKey, &physicalCameraId);
            if (!found) {
                ALOGE("%s: Cannot find physical camera ID!", __FUNCTION__);
                return;
            }
            (*cb)(context, cameraId.c_str(), physicalCameraId.c_str());
            break;
        }
        default:
            ALOGE("%s: unknown message type %d", __FUNCTION__, msg->what());
            break;
    }
}

void CameraManagerGlobal::CallbackHandler::notifyParent() {
    std::shared_ptr<CameraManagerGlobal> parent = mParent.lock();
    if (parent != nullptr) {
        parent->onCallbackCalled();
    }
}

ScopedAStatus CameraManagerGlobal::CameraServiceListener::onStatusChanged(
        CameraDeviceStatus status, const std::string &cameraId) {
    std::shared_ptr<CameraManagerGlobal> cm = mCameraManager.lock();
    if (cm != nullptr) {
        cm->onStatusChanged(status, cameraId);
    } else {
        ALOGE("Cannot deliver status change. Global camera manager died");
    }
    return ScopedAStatus::ok();
}

void CameraManagerGlobal::onStatusChanged(
        const CameraDeviceStatus &status, const std::string &cameraId) {
    Mutex::Autolock _l(mLock);
    onStatusChangedLocked(status, cameraId);
}

void CameraManagerGlobal::onStatusChangedLocked(
        const CameraDeviceStatus &status, const std::string &cameraId) {
    if (!validStatus(status)) {
        ALOGE("%s: Invalid status %d", __FUNCTION__, status);
        return;
    }

    bool firstStatus = (mDeviceStatusMap.count(cameraId) == 0);
    CameraDeviceStatus oldStatus = firstStatus ?
            status : // first status
            mDeviceStatusMap[cameraId].getStatus();

    if (!firstStatus &&
            isStatusAvailable(status) == isStatusAvailable(oldStatus)) {
        // No status update. No need to send callback
        return;
    }

    // Iterate through all registered callbacks
    mDeviceStatusMap[cameraId].updateStatus(status);
    for (auto cb : mCallbacks) {
        sp<AMessage> msg = new AMessage(kWhatSendSingleCallback, mHandler);
        ACameraManager_AvailabilityCallback cbFp = isStatusAvailable(status) ?
                cb.mAvailable : cb.mUnavailable;
        msg->setPointer(kCallbackFpKey, (void *) cbFp);
        msg->setPointer(kContextKey, cb.mContext);
        msg->setString(kCameraIdKey, AString(cameraId.c_str()));
        mPendingCallbackCnt++;
        msg->post();
    }
    if (status == CameraDeviceStatus::STATUS_NOT_PRESENT) {
        mDeviceStatusMap.erase(cameraId);
    }
}

ScopedAStatus CameraManagerGlobal::CameraServiceListener::onPhysicalCameraStatusChanged(
        CameraDeviceStatus in_status, const std::string& in_cameraId,
        const std::string& in_physicalCameraId) {
    std::shared_ptr<CameraManagerGlobal> cm = mCameraManager.lock();
    if (cm != nullptr) {
        cm->onStatusChanged(in_status, in_cameraId, in_physicalCameraId);
    } else {
        ALOGE("Cannot deliver status change. Global camera manager died");
    }
    return ScopedAStatus::ok();
}

void CameraManagerGlobal::onStatusChanged(
        const CameraDeviceStatus &status, const std::string& cameraId,
        const std::string& physicalCameraId) {
    Mutex::Autolock _l(mLock);
    onStatusChangedLocked(status, cameraId, physicalCameraId);
}

void CameraManagerGlobal::onStatusChangedLocked(
        const CameraDeviceStatus &status, const std::string& cameraId,
        const std::string& physicalCameraId) {
    if (!validStatus(status)) {
        ALOGE("%s: Invalid status %d", __FUNCTION__, status);
        return;
    }

    auto logicalStatus = mDeviceStatusMap.find(cameraId);
    if (logicalStatus == mDeviceStatusMap.end()) {
        ALOGE("%s: Physical camera id %s status change on a non-present id %s",
                __FUNCTION__, physicalCameraId.c_str(), cameraId.c_str());
        return;
    }
    CameraDeviceStatus logicalCamStatus = mDeviceStatusMap[cameraId].getStatus();
    if (logicalCamStatus != CameraDeviceStatus::STATUS_PRESENT &&
            logicalCamStatus != CameraDeviceStatus::STATUS_NOT_AVAILABLE) {
        ALOGE("%s: Physical camera id %s status %d change for an invalid logical camera state %d",
                __FUNCTION__, physicalCameraId.c_str(), status, logicalCamStatus);
        return;
    }

    bool updated = false;
    if (status == CameraDeviceStatus::STATUS_PRESENT) {
        updated = mDeviceStatusMap[cameraId].removeUnavailablePhysicalId(physicalCameraId);
    } else {
        updated = mDeviceStatusMap[cameraId].addUnavailablePhysicalId(physicalCameraId);
    }

    // Iterate through all registered callbacks
    if (updated) {
        for (auto cb : mCallbacks) {
            sp<AMessage> msg = new AMessage(kWhatSendSinglePhysicalCameraCallback, mHandler);
            ACameraManager_PhysicalCameraAvailabilityCallback cbFp = isStatusAvailable(status) ?
                    cb.mPhysicalCamAvailable : cb.mPhysicalCamUnavailable;
            msg->setPointer(kCallbackFpKey, (void *) cbFp);
            msg->setPointer(kContextKey, cb.mContext);
            msg->setString(kCameraIdKey, AString(cameraId.c_str()));
            msg->setString(kPhysicalCameraIdKey, AString(physicalCameraId.c_str()));
            mPendingCallbackCnt++;
            msg->post();
        }
    }
}

CameraDeviceStatus CameraManagerGlobal::CameraStatus::getStatus() {
    std::lock_guard<std::mutex> lock(mLock);
    return status;
}

void CameraManagerGlobal::CameraStatus::updateStatus(CameraDeviceStatus newStatus) {
    std::lock_guard<std::mutex> lock(mLock);
    status = newStatus;
}

bool CameraManagerGlobal::CameraStatus::addUnavailablePhysicalId(
        const std::string& physicalCameraId) {
    std::lock_guard<std::mutex> lock(mLock);
    auto result = unavailablePhysicalIds.insert(physicalCameraId);
    return result.second;
}

bool CameraManagerGlobal::CameraStatus::removeUnavailablePhysicalId(
        const std::string& physicalCameraId) {
    std::lock_guard<std::mutex> lock(mLock);
    auto count = unavailablePhysicalIds.erase(physicalCameraId);
    return count > 0;
}

std::set<std::string> CameraManagerGlobal::CameraStatus::getUnavailablePhysicalIds() {
    std::lock_guard<std::mutex> lock(mLock);
    return unavailablePhysicalIds;
}

} // namespace acam
} // namespace android

/**
 * ACameraManger Implementation
 */
camera_status_t ACameraManager::getCameraIdList(ACameraIdList** cameraIdList) {
    Mutex::Autolock _l(mLock);

    std::vector<std::string> idList;
    CameraManagerGlobal::getInstance()->getCameraIdList(&idList);

    int numCameras = idList.size();
    ACameraIdList *out = new ACameraIdList;
    if (out == nullptr) {
        ALOGE("Allocate memory for ACameraIdList failed!");
        return ACAMERA_ERROR_NOT_ENOUGH_MEMORY;
    }
    out->numCameras = numCameras;
    out->cameraIds = new const char*[numCameras];
    if (!out->cameraIds) {
        ALOGE("Allocate memory for ACameraIdList failed!");
        deleteCameraIdList(out);
        return ACAMERA_ERROR_NOT_ENOUGH_MEMORY;
    }
    for (int i = 0; i < numCameras; i++) {
        const char* src = idList[i].c_str();
        size_t dstSize = strlen(src) + 1;
        char* dst = new char[dstSize];
        if (!dst) {
            ALOGE("Allocate memory for ACameraIdList failed!");
            deleteCameraIdList(out);
            return ACAMERA_ERROR_NOT_ENOUGH_MEMORY;
        }
        strlcpy(dst, src, dstSize);
        out->cameraIds[i] = dst;
    }
    *cameraIdList = out;
    return ACAMERA_OK;
}

void
ACameraManager::deleteCameraIdList(ACameraIdList* cameraIdList) {
    if (cameraIdList != nullptr) {
        if (cameraIdList->cameraIds != nullptr) {
            for (int i = 0; i < cameraIdList->numCameras; i ++) {
                if (cameraIdList->cameraIds[i] != nullptr) {
                    delete[] cameraIdList->cameraIds[i];
                }
            }
            delete[] cameraIdList->cameraIds;
        }
        delete cameraIdList;
    }
}

camera_status_t ACameraManager::getCameraCharacteristics(const char *cameraIdStr,
                                                         sp<ACameraMetadata> *characteristics) {
    using AidlCameraMetadata = ::aidl::android::frameworks::cameraservice::device::CameraMetadata;
    Mutex::Autolock _l(mLock);

    std::shared_ptr<ICameraService> cs = CameraManagerGlobal::getInstance()->getCameraService();
    if (cs == nullptr) {
        ALOGE("%s: Cannot reach camera service!", __FUNCTION__);
        return ACAMERA_ERROR_CAMERA_DISCONNECTED;
    }
    AidlCameraMetadata rawMetadata;
    ScopedAStatus serviceRet = cs->getCameraCharacteristics(cameraIdStr, &rawMetadata);

    if (!serviceRet.isOk()) {
        if (serviceRet.getExceptionCode() == EX_SERVICE_SPECIFIC) {
            Status errStatus = static_cast<Status>(serviceRet.getServiceSpecificError());
            ALOGE("%s: Get camera characteristics from camera service failed: %s",
                __FUNCTION__, toString(errStatus).c_str());
        } else {
            ALOGE("%s: Transaction error when getting camera "
                  "characteristics from camera service: %d",
                __FUNCTION__, serviceRet.getExceptionCode());
        }
        return ACAMERA_ERROR_UNKNOWN; // should not reach here
    }

    camera_metadata_t* metadataBuffer;
    ::android::acam::utils::cloneFromAidl(rawMetadata, &metadataBuffer);

    *characteristics = new ACameraMetadata(metadataBuffer,
                                           ACameraMetadata::ACM_CHARACTERISTICS);
    return ACAMERA_OK;
}

camera_status_t
ACameraManager::openCamera(
        const char* cameraId,
        ACameraDevice_StateCallbacks* callback,
        /*out*/ACameraDevice** outDevice) {
    sp<ACameraMetadata> rawChars;
    camera_status_t ret = getCameraCharacteristics(cameraId, &rawChars);
    Mutex::Autolock _l(mLock);
    if (ret != ACAMERA_OK) {
        ALOGE("%s: cannot get camera characteristics for camera %s. err %d",
                __FUNCTION__, cameraId, ret);
        return ACAMERA_ERROR_INVALID_PARAMETER;
    }

    ACameraDevice* device = new ACameraDevice(cameraId, callback, std::move(rawChars));

    std::shared_ptr<ICameraService> cs = CameraManagerGlobal::getInstance()->getCameraService();
    if (cs == nullptr) {
        ALOGE("%s: Cannot reach camera service!", __FUNCTION__);
        delete device;
        return ACAMERA_ERROR_CAMERA_DISCONNECTED;
    }

    std::shared_ptr<BnCameraDeviceCallback> deviceCallback = device->getServiceCallback();
    std::shared_ptr<ICameraDeviceUser> deviceRemote;

    // No way to get package name from native.
    // Send a zero length package name and let camera service figure it out from UID
    ScopedAStatus serviceRet = cs->connectDevice(deviceCallback,
                                                 std::string(cameraId), &deviceRemote);
    if (!serviceRet.isOk()) {
        if (serviceRet.getExceptionCode() == EX_SERVICE_SPECIFIC) {
            Status errStatus = static_cast<Status>(serviceRet.getServiceSpecificError());
            ALOGE("%s: connect camera device failed: %s",
                  __FUNCTION__, toString(errStatus).c_str());
            delete device;
            return utils::convertFromAidl(errStatus);
        } else {
            ALOGE("%s: Transaction failed when connecting camera device: %d",
                __FUNCTION__, serviceRet.getExceptionCode());
            delete device;
            return ACAMERA_ERROR_UNKNOWN;
        }
    }

    if (deviceRemote == nullptr) {
        ALOGE("%s: connect camera device failed! remote device is null", __FUNCTION__);
        delete device;
        return ACAMERA_ERROR_CAMERA_DISCONNECTED;
    }

    device->setRemoteDevice(deviceRemote);
    device->setDeviceMetadataQueues();
    *outDevice = device;
    return ACAMERA_OK;
}

camera_status_t
ACameraManager::getTagFromName(const char *cameraId, const char *name, uint32_t *tag) {
    sp<ACameraMetadata> rawChars;
    camera_status_t ret = getCameraCharacteristics(cameraId, &rawChars);
    if (ret != ACAMERA_OK) {
        ALOGE("%s, Cannot retrieve camera characteristics for camera id %s", __FUNCTION__,
                cameraId);
        return ACAMERA_ERROR_METADATA_NOT_FOUND;
    }
    const CameraMetadata& metadata = rawChars->getInternalData();
    const camera_metadata_t *rawMetadata = metadata.getAndLock();
    metadata_vendor_id_t vendorTagId = get_camera_metadata_vendor_id(rawMetadata);
    metadata.unlock(rawMetadata);
    sp<VendorTagDescriptorCache> vtCache = VendorTagDescriptorCache::getGlobalVendorTagCache();
    sp<VendorTagDescriptor> vTags = nullptr;
    vtCache->getVendorTagDescriptor(vendorTagId, &vTags);
    status_t status = CameraMetadata::getTagFromName(name, vTags.get(), tag);
    return status == OK ? ACAMERA_OK : ACAMERA_ERROR_METADATA_NOT_FOUND;
}

ACameraManager::~ACameraManager() {

}
