/*
 * Copyright (C) 2016 The Android Open Source Project
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

#define LOG_TAG "CameraProviderManager"
#define ATRACE_TAG ATRACE_TAG_CAMERA
//#define LOG_NDEBUG 0

#include "CameraProviderManager.h"

#include <aidl/android/hardware/camera/device/ICameraDevice.h>

#include <algorithm>
#include <chrono>
#include "common/DepthPhotoProcessor.h"
#include "hidl/HidlProviderInfo.h"
#include "aidl/AidlProviderInfo.h"
#include <dlfcn.h>
#include <future>
#include <inttypes.h>
#include <android/binder_manager.h>
#include <android/hidl/manager/1.2/IServiceManager.h>
#include <hidl/ServiceManagement.h>
#include <functional>
#include <camera_metadata_hidden.h>
#include <android-base/parseint.h>
#include <android-base/logging.h>
#include <cutils/properties.h>
#include <hwbinder/IPCThreadState.h>
#include <utils/Trace.h>

#include "api2/HeicCompositeStream.h"
#include "device3/ZoomRatioMapper.h"

namespace android {

using namespace ::android::hardware::camera;
using namespace ::android::camera3;
using android::hardware::camera::common::V1_0::Status;
using namespace camera3::SessionConfigurationUtils;
using std::literals::chrono_literals::operator""s;
using hardware::camera2::utils::CameraIdAndSessionConfiguration;

namespace {
const bool kEnableLazyHal(property_get_bool("ro.camera.enableLazyHal", false));
const std::string kExternalProviderName = "external/0";
} // anonymous namespace

const float CameraProviderManager::kDepthARTolerance = .1f;

CameraProviderManager::HidlServiceInteractionProxyImpl
CameraProviderManager::sHidlServiceInteractionProxy{};

CameraProviderManager::~CameraProviderManager() {
}

const char* FrameworkTorchStatusToString(const TorchModeStatus& s) {
    switch (s) {
        case TorchModeStatus::NOT_AVAILABLE:
            return "NOT_AVAILABLE";
        case TorchModeStatus::AVAILABLE_OFF:
            return "AVAILABLE_OFF";
        case TorchModeStatus::AVAILABLE_ON:
            return "AVAILABLE_ON";
    }
    ALOGW("Unexpected HAL torch mode status code %d", s);
    return "UNKNOWN_STATUS";
}

const char* FrameworkDeviceStatusToString(const CameraDeviceStatus& s) {
    switch (s) {
        case CameraDeviceStatus::NOT_PRESENT:
            return "NOT_PRESENT";
        case CameraDeviceStatus::PRESENT:
            return "PRESENT";
        case CameraDeviceStatus::ENUMERATING:
            return "ENUMERATING";
    }
    ALOGW("Unexpected HAL device status code %d", s);
    return "UNKNOWN_STATUS";
}

hardware::hidl_vec<hardware::hidl_string>
CameraProviderManager::HidlServiceInteractionProxyImpl::listServices() {
    hardware::hidl_vec<hardware::hidl_string> ret;
    auto manager = hardware::defaultServiceManager1_2();
    if (manager != nullptr) {
        manager->listManifestByInterface(provider::V2_4::ICameraProvider::descriptor,
                [&ret](const hardware::hidl_vec<hardware::hidl_string> &registered) {
                    ret = registered;
                });
    }
    return ret;
}

status_t CameraProviderManager::tryToInitAndAddHidlProvidersLocked(
        HidlServiceInteractionProxy *hidlProxy) {
    mHidlServiceProxy = hidlProxy;
    // Registering will trigger notifications for all already-known providers
    bool success = mHidlServiceProxy->registerForNotifications(
        /* instance name, empty means no filter */ "",
        this);
    if (!success) {
        ALOGE("%s: Unable to register with hardware service manager for notifications "
                "about camera providers", __FUNCTION__);
        return INVALID_OPERATION;
    }

    for (const auto& instance : mHidlServiceProxy->listServices()) {
        this->addHidlProviderLocked(instance);
    }
    return OK;
}

static std::string getFullAidlProviderName(const std::string instance) {
    std::string aidlHalServiceDescriptor =
            std::string(aidl::android::hardware::camera::provider::ICameraProvider::descriptor);
   return aidlHalServiceDescriptor + "/" + instance;
}

status_t CameraProviderManager::tryToAddAidlProvidersLocked() {
    const char * aidlHalServiceDescriptor =
            aidl::android::hardware::camera::provider::ICameraProvider::descriptor;
    auto sm = defaultServiceManager();
    auto aidlProviders = sm->getDeclaredInstances(
            String16(aidlHalServiceDescriptor));
    for (const auto &aidlInstance : aidlProviders) {
        std::string aidlServiceName =
                getFullAidlProviderName(std::string(String8(aidlInstance).c_str()));
        auto res = sm->registerForNotifications(String16(aidlServiceName.c_str()), this);
        if (res != OK) {
            ALOGE("%s Unable to register for notifications with AIDL service manager",
                    __FUNCTION__);
            return res;
        }
        addAidlProviderLocked(aidlServiceName);
    }
    return OK;
}

status_t CameraProviderManager::initialize(wp<CameraProviderManager::StatusListener> listener,
        HidlServiceInteractionProxy* hidlProxy) {
    std::lock_guard<std::mutex> lock(mInterfaceMutex);
    if (hidlProxy == nullptr) {
        ALOGE("%s: No valid service interaction proxy provided", __FUNCTION__);
        return BAD_VALUE;
    }
    mListener = listener;
    mDeviceState = 0;
    auto res = tryToInitAndAddHidlProvidersLocked(hidlProxy);
    if (res != OK) {
        // Logging done in called function;
        return res;
    }
    res = tryToAddAidlProvidersLocked();

    IPCThreadState::self()->flushCommands();

    return res;
}

std::pair<int, int> CameraProviderManager::getCameraCount() const {
    std::lock_guard<std::mutex> lock(mInterfaceMutex);
    int systemCameraCount = 0;
    int publicCameraCount = 0;
    for (auto& provider : mProviders) {
        for (auto &id : provider->mUniqueCameraIds) {
            SystemCameraKind deviceKind = SystemCameraKind::PUBLIC;
            if (getSystemCameraKindLocked(id, &deviceKind) != OK) {
                ALOGE("%s: Invalid camera id %s, skipping", __FUNCTION__, id.c_str());
                continue;
            }
            switch(deviceKind) {
                case SystemCameraKind::PUBLIC:
                    publicCameraCount++;
                    break;
                case SystemCameraKind::SYSTEM_ONLY_CAMERA:
                    systemCameraCount++;
                    break;
                default:
                    break;
            }
        }
    }
    return std::make_pair(systemCameraCount, publicCameraCount);
}

std::vector<std::string> CameraProviderManager::getCameraDeviceIds() const {
    std::lock_guard<std::mutex> lock(mInterfaceMutex);
    std::vector<std::string> deviceIds;
    for (auto& provider : mProviders) {
        for (auto& id : provider->mUniqueCameraIds) {
            deviceIds.push_back(id);
        }
    }
    return deviceIds;
}

void CameraProviderManager::collectDeviceIdsLocked(const std::vector<std::string> deviceIds,
        std::vector<std::string>& publicDeviceIds,
        std::vector<std::string>& systemDeviceIds) const {
    for (auto &deviceId : deviceIds) {
        SystemCameraKind deviceKind = SystemCameraKind::PUBLIC;
        if (getSystemCameraKindLocked(deviceId, &deviceKind) != OK) {
            ALOGE("%s: Invalid camera id %s, skipping", __FUNCTION__, deviceId.c_str());
            continue;
        }
        if (deviceKind == SystemCameraKind::SYSTEM_ONLY_CAMERA) {
            systemDeviceIds.push_back(deviceId);
        } else {
            publicDeviceIds.push_back(deviceId);
        }
    }
}

std::vector<std::string> CameraProviderManager::getAPI1CompatibleCameraDeviceIds() const {
    std::lock_guard<std::mutex> lock(mInterfaceMutex);
    std::vector<std::string> publicDeviceIds;
    std::vector<std::string> systemDeviceIds;
    std::vector<std::string> deviceIds;
    for (auto& provider : mProviders) {
        std::vector<std::string> providerDeviceIds = provider->mUniqueAPI1CompatibleCameraIds;
        // Secure cameras should not be exposed through camera 1 api
        providerDeviceIds.erase(std::remove_if(providerDeviceIds.begin(), providerDeviceIds.end(),
                [this](const std::string& s) {
                SystemCameraKind deviceKind = SystemCameraKind::PUBLIC;
                if (getSystemCameraKindLocked(s, &deviceKind) != OK) {
                    ALOGE("%s: Invalid camera id %s, skipping", __FUNCTION__, s.c_str());
                    return true;
                }
                return deviceKind == SystemCameraKind::HIDDEN_SECURE_CAMERA;}),
                providerDeviceIds.end());
        // API1 app doesn't handle logical and physical camera devices well. So
        // for each camera facing, only take the first id advertised by HAL in
        // all [logical, physical1, physical2, ...] id combos, and filter out the rest.
        filterLogicalCameraIdsLocked(providerDeviceIds);
        collectDeviceIdsLocked(providerDeviceIds, publicDeviceIds, systemDeviceIds);
    }
    auto sortFunc =
            [](const std::string& a, const std::string& b) -> bool {
                uint32_t aUint = 0, bUint = 0;
                bool aIsUint = base::ParseUint(a, &aUint);
                bool bIsUint = base::ParseUint(b, &bUint);

                // Uint device IDs first
                if (aIsUint && bIsUint) {
                    return aUint < bUint;
                } else if (aIsUint) {
                    return true;
                } else if (bIsUint) {
                    return false;
                }
                // Simple string compare if both id are not uint
                return a < b;
            };
    // We put device ids for system cameras at the end since they will be pared
    // off for processes not having system camera permissions.
    std::sort(publicDeviceIds.begin(), publicDeviceIds.end(), sortFunc);
    std::sort(systemDeviceIds.begin(), systemDeviceIds.end(), sortFunc);
    deviceIds.insert(deviceIds.end(), publicDeviceIds.begin(), publicDeviceIds.end());
    deviceIds.insert(deviceIds.end(), systemDeviceIds.begin(), systemDeviceIds.end());
    return deviceIds;
}

bool CameraProviderManager::isValidDeviceLocked(const std::string &id, uint16_t majorVersion,
        IPCTransport transport) const {
    for (auto& provider : mProviders) {
        IPCTransport providerTransport = provider->getIPCTransport();
        for (auto& deviceInfo : provider->mDevices) {
            if (deviceInfo->mId == id && deviceInfo->mVersion.get_major() == majorVersion &&
                    transport == providerTransport) {
                return true;
            }
        }
    }
    return false;
}

bool CameraProviderManager::hasFlashUnit(const std::string &id) const {
    std::lock_guard<std::mutex> lock(mInterfaceMutex);

    auto deviceInfo = findDeviceInfoLocked(id);
    if (deviceInfo == nullptr) return false;

    return deviceInfo->hasFlashUnit();
}

bool CameraProviderManager::supportNativeZoomRatio(const std::string &id) const {
    std::lock_guard<std::mutex> lock(mInterfaceMutex);

    auto deviceInfo = findDeviceInfoLocked(id);
    if (deviceInfo == nullptr) return false;

    return deviceInfo->supportNativeZoomRatio();
}

status_t CameraProviderManager::getResourceCost(const std::string &id,
        CameraResourceCost* cost) const {
    std::lock_guard<std::mutex> lock(mInterfaceMutex);

    auto deviceInfo = findDeviceInfoLocked(id);
    if (deviceInfo == nullptr) return NAME_NOT_FOUND;

    *cost = deviceInfo->mResourceCost;
    return OK;
}

status_t CameraProviderManager::getCameraInfo(const std::string &id,
        hardware::CameraInfo* info) const {
    std::lock_guard<std::mutex> lock(mInterfaceMutex);

    auto deviceInfo = findDeviceInfoLocked(id);
    if (deviceInfo == nullptr) return NAME_NOT_FOUND;

    return deviceInfo->getCameraInfo(info);
}

status_t CameraProviderManager::isSessionConfigurationSupported(const std::string& id,
        const SessionConfiguration &configuration, bool overrideForPerfClass,
        metadataGetter getMetadata, bool *status /*out*/) const {
    std::lock_guard<std::mutex> lock(mInterfaceMutex);
    auto deviceInfo = findDeviceInfoLocked(id);
    if (deviceInfo == nullptr) {
        return NAME_NOT_FOUND;
    }

    return deviceInfo->isSessionConfigurationSupported(configuration,
            overrideForPerfClass, getMetadata, status);
}

status_t CameraProviderManager::getCameraIdIPCTransport(const std::string &id,
        IPCTransport *providerTransport) const {
    std::lock_guard<std::mutex> lock(mInterfaceMutex);
    auto deviceInfo = findDeviceInfoLocked(id);
    if (deviceInfo == nullptr) {
        return NAME_NOT_FOUND;
    }
    sp<ProviderInfo> parentProvider = deviceInfo->mParentProvider.promote();
    if (parentProvider == nullptr) {
        return DEAD_OBJECT;
    }
    *providerTransport = parentProvider->getIPCTransport();
    return OK;
}

status_t CameraProviderManager::getCameraCharacteristics(const std::string &id,
        bool overrideForPerfClass, CameraMetadata* characteristics) const {
    std::lock_guard<std::mutex> lock(mInterfaceMutex);
    return getCameraCharacteristicsLocked(id, overrideForPerfClass, characteristics);
}

status_t CameraProviderManager::getHighestSupportedVersion(const std::string &id,
        hardware::hidl_version *v, IPCTransport *transport) {
    if (v == nullptr || transport == nullptr) {
        return BAD_VALUE;
    }
    std::lock_guard<std::mutex> lock(mInterfaceMutex);

    hardware::hidl_version maxVersion{0,0};
    bool found = false;
    IPCTransport providerTransport = IPCTransport::INVALID;
    for (auto& provider : mProviders) {
        for (auto& deviceInfo : provider->mDevices) {
            if (deviceInfo->mId == id) {
                if (deviceInfo->mVersion > maxVersion) {
                    maxVersion = deviceInfo->mVersion;
                    providerTransport = provider->getIPCTransport();
                    found = true;
                }
            }
        }
    }
    if (!found || providerTransport == IPCTransport::INVALID) {
        return NAME_NOT_FOUND;
    }
    *v = maxVersion;
    *transport = providerTransport;
    return OK;
}

status_t CameraProviderManager::getTorchStrengthLevel(const std::string &id,
        int32_t* torchStrength /*out*/) {
    std::lock_guard<std::mutex> lock(mInterfaceMutex);

    auto deviceInfo = findDeviceInfoLocked(id);
    if (deviceInfo == nullptr) return NAME_NOT_FOUND;

    return deviceInfo->getTorchStrengthLevel(torchStrength);
}

status_t CameraProviderManager::turnOnTorchWithStrengthLevel(const std::string &id,
        int32_t torchStrength) {
    std::lock_guard<std::mutex> lock(mInterfaceMutex);

    auto deviceInfo = findDeviceInfoLocked(id);
    if (deviceInfo == nullptr) return NAME_NOT_FOUND;

    return deviceInfo->turnOnTorchWithStrengthLevel(torchStrength);
}

bool CameraProviderManager::shouldSkipTorchStrengthUpdate(const std::string &id,
        int32_t torchStrength) const {
    std::lock_guard<std::mutex> lock(mInterfaceMutex);

    auto deviceInfo = findDeviceInfoLocked(id);
    if (deviceInfo == nullptr) return NAME_NOT_FOUND;

    if (deviceInfo->mTorchStrengthLevel == torchStrength) {
        ALOGV("%s: Skipping torch strength level updates prev_level: %d, new_level: %d",
                __FUNCTION__, deviceInfo->mTorchStrengthLevel, torchStrength);
        return true;
    }
    return false;
}

int32_t CameraProviderManager::getTorchDefaultStrengthLevel(const std::string &id) const {
    std::lock_guard<std::mutex> lock(mInterfaceMutex);

    auto deviceInfo = findDeviceInfoLocked(id);
    if (deviceInfo == nullptr) return NAME_NOT_FOUND;

    return deviceInfo->mTorchDefaultStrengthLevel;
}

bool CameraProviderManager::supportSetTorchMode(const std::string &id) const {
    std::lock_guard<std::mutex> lock(mInterfaceMutex);
    for (auto& provider : mProviders) {
        for (auto& deviceInfo : provider->mDevices) {
            if (deviceInfo->mId == id) {
                return provider->mSetTorchModeSupported;
            }
        }
    }
    return false;
}

template <class ProviderInfoType, class HalCameraProviderType>
status_t CameraProviderManager::setTorchModeT(sp<ProviderInfo> &parentProvider,
        std::shared_ptr<HalCameraProvider> *halCameraProvider) {
    if (halCameraProvider == nullptr) {
        return BAD_VALUE;
    }
    ProviderInfoType *idlProviderInfo = static_cast<ProviderInfoType *>(parentProvider.get());
    auto idlInterface = idlProviderInfo->startProviderInterface();
    if (idlInterface == nullptr) {
        return DEAD_OBJECT;
    }
    *halCameraProvider =
            std::make_shared<HalCameraProviderType>(idlInterface, idlInterface->descriptor);
    return OK;
}

status_t CameraProviderManager::setTorchMode(const std::string &id, bool enabled) {
    std::lock_guard<std::mutex> lock(mInterfaceMutex);

    auto deviceInfo = findDeviceInfoLocked(id);
    if (deviceInfo == nullptr) return NAME_NOT_FOUND;

    // Pass the camera ID to start interface so that it will save it to the map of ICameraProviders
    // that are currently in use.
    sp<ProviderInfo> parentProvider = deviceInfo->mParentProvider.promote();
    if (parentProvider == nullptr) {
        return DEAD_OBJECT;
    }
    std::shared_ptr<HalCameraProvider> halCameraProvider = nullptr;
    IPCTransport providerTransport = parentProvider->getIPCTransport();
    status_t res = OK;
    if (providerTransport == IPCTransport::HIDL) {
        res = setTorchModeT<HidlProviderInfo, HidlHalCameraProvider>(parentProvider,
                &halCameraProvider);
        if (res != OK) {
            return res;
        }
    } else if (providerTransport == IPCTransport::AIDL) {
        res = setTorchModeT<AidlProviderInfo, AidlHalCameraProvider>(parentProvider,
                &halCameraProvider);
        if (res != OK) {
            return res;
        }
    } else {
        ALOGE("%s Invalid provider transport", __FUNCTION__);
        return INVALID_OPERATION;
    }
    saveRef(DeviceMode::TORCH, deviceInfo->mId, halCameraProvider);

    return deviceInfo->setTorchMode(enabled);
}

status_t CameraProviderManager::setUpVendorTags() {
    sp<VendorTagDescriptorCache> tagCache = new VendorTagDescriptorCache();

    for (auto& provider : mProviders) {
        tagCache->addVendorDescriptor(provider->mProviderTagid, provider->mVendorTagDescriptor);
    }

    VendorTagDescriptorCache::setAsGlobalVendorTagCache(tagCache);

    return OK;
}

sp<CameraProviderManager::ProviderInfo> CameraProviderManager::startExternalLazyProvider() const {
    std::lock_guard<std::mutex> providerLock(mProviderLifecycleLock);
    std::lock_guard<std::mutex> lock(mInterfaceMutex);

    for (const auto& providerInfo : mProviders) {
        if (providerInfo->isExternalLazyHAL()) {
            if (!providerInfo->successfullyStartedProviderInterface()) {
                return nullptr;
            } else {
                return providerInfo;
            }
        }
    }
    return nullptr;
}

status_t CameraProviderManager::notifyUsbDeviceEvent(int32_t eventId,
                                                     const std::string& usbDeviceId) {
    if (!kEnableLazyHal) {
        return OK;
    }

    ALOGV("notifySystemEvent: %d usbDeviceId : %s", eventId, usbDeviceId.c_str());

    if (eventId == android::hardware::ICameraService::EVENT_USB_DEVICE_ATTACHED) {
        sp<ProviderInfo> externalProvider = startExternalLazyProvider();
        if (externalProvider != nullptr) {
            auto usbDevices = mExternalUsbDevicesForProvider.first;
            usbDevices.push_back(usbDeviceId);
            mExternalUsbDevicesForProvider = {usbDevices, externalProvider};
        }
    } else if (eventId
          == android::hardware::ICameraService::EVENT_USB_DEVICE_DETACHED) {
        usbDeviceDetached(usbDeviceId);
    }

    return OK;
}

status_t CameraProviderManager::usbDeviceDetached(const std::string &usbDeviceId) {
    std::lock_guard<std::mutex> providerLock(mProviderLifecycleLock);
    std::lock_guard<std::mutex> interfaceLock(mInterfaceMutex);

    auto usbDevices = mExternalUsbDevicesForProvider.first;
    auto foundId = std::find(usbDevices.begin(), usbDevices.end(), usbDeviceId);
    if (foundId != usbDevices.end()) {
        sp<ProviderInfo> providerInfo = mExternalUsbDevicesForProvider.second;
        if (providerInfo == nullptr) {
              ALOGE("%s No valid external provider for USB device: %s",
                    __FUNCTION__,
                    usbDeviceId.c_str());
              mExternalUsbDevicesForProvider = {std::vector<std::string>(), nullptr};
              return DEAD_OBJECT;
        } else {
            mInterfaceMutex.unlock();
            providerInfo->removeAllDevices();
            mInterfaceMutex.lock();
            mExternalUsbDevicesForProvider = {std::vector<std::string>(), nullptr};
        }
    } else {
        return DEAD_OBJECT;
    }
    return OK;
}

status_t CameraProviderManager::notifyDeviceStateChange(int64_t newState) {
    std::lock_guard<std::mutex> lock(mInterfaceMutex);
    mDeviceState = newState;
    status_t res = OK;
    for (auto& provider : mProviders) {
        ALOGV("%s: Notifying %s for new state 0x%" PRIx64,
                __FUNCTION__, provider->mProviderName.c_str(), newState);
        // b/199240726 Camera providers can for example try to add/remove
        // camera devices as part of the state change notification. Holding
        // 'mInterfaceMutex' while calling 'notifyDeviceStateChange' can
        // result in a recursive deadlock.
        mInterfaceMutex.unlock();
        status_t singleRes = provider->notifyDeviceStateChange(mDeviceState);
        mInterfaceMutex.lock();
        if (singleRes != OK) {
            ALOGE("%s: Unable to notify provider %s about device state change",
                    __FUNCTION__,
                    provider->mProviderName.c_str());
            res = singleRes;
            // continue to do the rest of the providers instead of returning now
        }
        provider->notifyDeviceInfoStateChangeLocked(mDeviceState);
    }
    return res;
}

status_t CameraProviderManager::openAidlSession(const std::string &id,
        const std::shared_ptr<
                aidl::android::hardware::camera::device::ICameraDeviceCallback>& callback,
        /*out*/
        std::shared_ptr<aidl::android::hardware::camera::device::ICameraDeviceSession> *session) {

    std::lock_guard<std::mutex> lock(mInterfaceMutex);

    auto deviceInfo = findDeviceInfoLocked(id);
    if (deviceInfo == nullptr) return NAME_NOT_FOUND;

    auto *aidlDeviceInfo3 = static_cast<AidlProviderInfo::AidlDeviceInfo3*>(deviceInfo);
    sp<ProviderInfo> parentProvider = deviceInfo->mParentProvider.promote();
    if (parentProvider == nullptr) {
        return DEAD_OBJECT;
    }
    auto provider =
            static_cast<AidlProviderInfo *>(parentProvider.get())->startProviderInterface();
    if (provider == nullptr) {
        return DEAD_OBJECT;
    }
    std::shared_ptr<HalCameraProvider> halCameraProvider =
            std::make_shared<AidlHalCameraProvider>(provider, provider->descriptor);
    saveRef(DeviceMode::CAMERA, id, halCameraProvider);

    auto interface = aidlDeviceInfo3->startDeviceInterface();
    if (interface == nullptr) {
        removeRef(DeviceMode::CAMERA, id);
        return DEAD_OBJECT;
    }

    auto ret = interface->open(callback, session);
    if (!ret.isOk()) {
        removeRef(DeviceMode::CAMERA, id);
        ALOGE("%s: Transaction error opening a session for camera device %s: %s",
                __FUNCTION__, id.c_str(), ret.getMessage());
        return AidlProviderInfo::mapToStatusT(ret);
    }
    return OK;
}

status_t CameraProviderManager::openAidlInjectionSession(const std::string &id,
        const std::shared_ptr<
                aidl::android::hardware::camera::device::ICameraDeviceCallback>& callback,
        /*out*/
        std::shared_ptr<
                aidl::android::hardware::camera::device::ICameraInjectionSession> *session) {

    std::lock_guard<std::mutex> lock(mInterfaceMutex);

    auto deviceInfo = findDeviceInfoLocked(id);
    if (deviceInfo == nullptr) return NAME_NOT_FOUND;

    auto *aidlDeviceInfo3 = static_cast<AidlProviderInfo::AidlDeviceInfo3*>(deviceInfo);
    sp<ProviderInfo> parentProvider = deviceInfo->mParentProvider.promote();
    if (parentProvider == nullptr) {
        return DEAD_OBJECT;
    }
    auto provider =
            static_cast<AidlProviderInfo *>(parentProvider.get())->startProviderInterface();
    if (provider == nullptr) {
        return DEAD_OBJECT;
    }
    std::shared_ptr<HalCameraProvider> halCameraProvider =
            std::make_shared<AidlHalCameraProvider>(provider, provider->descriptor);
    saveRef(DeviceMode::CAMERA, id, halCameraProvider);

    auto interface = aidlDeviceInfo3->startDeviceInterface();
    if (interface == nullptr) {
        return DEAD_OBJECT;
    }

    auto ret = interface->openInjectionSession(callback, session);
    if (!ret.isOk()) {
        removeRef(DeviceMode::CAMERA, id);
        ALOGE("%s: Transaction error opening a session for camera device %s: %s",
                __FUNCTION__, id.c_str(), ret.getMessage());
        return DEAD_OBJECT;
    }
    return OK;
}

status_t CameraProviderManager::openHidlSession(const std::string &id,
        const sp<device::V3_2::ICameraDeviceCallback>& callback,
        /*out*/
        sp<device::V3_2::ICameraDeviceSession> *session) {

    std::lock_guard<std::mutex> lock(mInterfaceMutex);

    auto deviceInfo = findDeviceInfoLocked(id);
    if (deviceInfo == nullptr) return NAME_NOT_FOUND;

    auto *hidlDeviceInfo3 = static_cast<HidlProviderInfo::HidlDeviceInfo3*>(deviceInfo);
    sp<ProviderInfo> parentProvider = deviceInfo->mParentProvider.promote();
    if (parentProvider == nullptr) {
        return DEAD_OBJECT;
    }
    const sp<provider::V2_4::ICameraProvider> provider =
            static_cast<HidlProviderInfo *>(parentProvider.get())->startProviderInterface();
    if (provider == nullptr) {
        return DEAD_OBJECT;
    }
    std::shared_ptr<HalCameraProvider> halCameraProvider =
            std::make_shared<HidlHalCameraProvider>(provider, provider->descriptor);
    saveRef(DeviceMode::CAMERA, id, halCameraProvider);

    Status status;
    hardware::Return<void> ret;
    auto interface = hidlDeviceInfo3->startDeviceInterface();
    if (interface == nullptr) {
        return DEAD_OBJECT;
    }

    ret = interface->open(callback, [&status, &session]
            (Status s, const sp<device::V3_2::ICameraDeviceSession>& cameraSession) {
                status = s;
                if (status == Status::OK) {
                    *session = cameraSession;
                }
            });
    if (!ret.isOk()) {
        removeRef(DeviceMode::CAMERA, id);
        ALOGE("%s: Transaction error opening a session for camera device %s: %s",
                __FUNCTION__, id.c_str(), ret.description().c_str());
        return DEAD_OBJECT;
    }
    return HidlProviderInfo::mapToStatusT(status);
}

void CameraProviderManager::saveRef(DeviceMode usageType, const std::string &cameraId,
        std::shared_ptr<HalCameraProvider> provider) {
    if (!kEnableLazyHal) {
        return;
    }
    ALOGV("Saving camera provider %s for camera device %s", provider->mDescriptor.c_str(),
              cameraId.c_str());
    std::lock_guard<std::mutex> lock(mProviderInterfaceMapLock);
    std::unordered_map<std::string, std::shared_ptr<HalCameraProvider>> *primaryMap, *alternateMap;
    if (usageType == DeviceMode::TORCH) {
        primaryMap = &mTorchProviderByCameraId;
        alternateMap = &mCameraProviderByCameraId;
    } else {
        primaryMap = &mCameraProviderByCameraId;
        alternateMap = &mTorchProviderByCameraId;
    }
    auto id = cameraId.c_str();
    (*primaryMap)[id] = provider;
    auto search = alternateMap->find(id);
    if (search != alternateMap->end()) {
        ALOGW("%s: Camera device %s is using both torch mode and camera mode simultaneously. "
                "That should not be possible", __FUNCTION__, id);
    }
    ALOGV("%s: Camera device %s connected", __FUNCTION__, id);
}

void CameraProviderManager::removeRef(DeviceMode usageType, const std::string &cameraId) {
    if (!kEnableLazyHal) {
        return;
    }
    ALOGV("Removing camera device %s", cameraId.c_str());
    std::unordered_map<std::string, std::shared_ptr<HalCameraProvider>> *providerMap;
    if (usageType == DeviceMode::TORCH) {
        providerMap = &mTorchProviderByCameraId;
    } else {
        providerMap = &mCameraProviderByCameraId;
    }
    std::lock_guard<std::mutex> lock(mProviderInterfaceMapLock);
    auto search = providerMap->find(cameraId.c_str());
    if (search != providerMap->end()) {
        // Drop the reference to this ICameraProvider. This is safe to do immediately (without an
        // added delay) because hwservicemanager guarantees to hold the reference for at least five
        // more seconds.  We depend on this behavior so that if the provider is unreferenced and
        // then referenced again quickly, we do not let the HAL exit and then need to immediately
        // restart it. An example when this could happen is switching from a front-facing to a
        // rear-facing camera. If the HAL were to exit during the camera switch, the camera could
        // appear janky to the user.
        providerMap->erase(cameraId.c_str());
        IPCThreadState::self()->flushCommands();
    } else {
        ALOGE("%s: Asked to remove reference for camera %s, but no reference to it was found. This "
                "could mean removeRef was called twice for the same camera ID.", __FUNCTION__,
                cameraId.c_str());
    }
}

// We ignore sp<IBinder> param here since we need std::shared_ptr<...> which
// will be retrieved through the ndk api through addAidlProviderLocked ->
// tryToInitializeAidlProvider.
void CameraProviderManager::onServiceRegistration(const String16 &name, const sp<IBinder>&) {
    status_t res = OK;
    std::lock_guard<std::mutex> providerLock(mProviderLifecycleLock);
    {
        std::lock_guard<std::mutex> lock(mInterfaceMutex);

        res = addAidlProviderLocked(String8(name).c_str());
    }

    sp<StatusListener> listener = getStatusListener();
    if (nullptr != listener.get() && res == OK) {
        listener->onNewProviderRegistered();
    }

    IPCThreadState::self()->flushCommands();
}

hardware::Return<void> CameraProviderManager::onRegistration(
        const hardware::hidl_string& /*fqName*/,
        const hardware::hidl_string& name,
        bool preexisting) {
    status_t res = OK;
    std::lock_guard<std::mutex> providerLock(mProviderLifecycleLock);
    {
        std::lock_guard<std::mutex> lock(mInterfaceMutex);

        res = addHidlProviderLocked(name, preexisting);
    }

    sp<StatusListener> listener = getStatusListener();
    if (nullptr != listener.get() && res == OK) {
        listener->onNewProviderRegistered();
    }

    IPCThreadState::self()->flushCommands();

    return hardware::Return<void>();
}

status_t CameraProviderManager::dump(int fd, const Vector<String16>& args) {
    std::lock_guard<std::mutex> lock(mInterfaceMutex);

    for (auto& provider : mProviders) {
        provider->dump(fd, args);
    }
    return OK;
}

void CameraProviderManager::ProviderInfo::initializeProviderInfoCommon(
        const std::vector<std::string> &devices) {

    sp<StatusListener> listener = mManager->getStatusListener();

    for (auto& device : devices) {
        std::string id;
        status_t res = addDevice(device, CameraDeviceStatus::PRESENT, &id);
        if (res != OK) {
            ALOGE("%s: Unable to enumerate camera device '%s': %s (%d)",
                    __FUNCTION__, device.c_str(), strerror(-res), res);
            continue;
        }
    }

    ALOGI("Camera provider %s ready with %zu camera devices",
            mProviderName.c_str(), mDevices.size());

    // Process cached status callbacks
    std::unique_ptr<std::vector<CameraStatusInfoT>> cachedStatus =
            std::make_unique<std::vector<CameraStatusInfoT>>();
    {
        std::lock_guard<std::mutex> lock(mInitLock);

        for (auto& statusInfo : mCachedStatus) {
            std::string id, physicalId;
            status_t res = OK;
            if (statusInfo.isPhysicalCameraStatus) {
                res = physicalCameraDeviceStatusChangeLocked(&id, &physicalId,
                    statusInfo.cameraId, statusInfo.physicalCameraId, statusInfo.status);
            } else {
                res = cameraDeviceStatusChangeLocked(&id, statusInfo.cameraId, statusInfo.status);
            }
            if (res == OK) {
                cachedStatus->emplace_back(statusInfo.isPhysicalCameraStatus,
                        id.c_str(), physicalId.c_str(), statusInfo.status);
            }
        }
        mCachedStatus.clear();

        mInitialized = true;
    }

    // The cached status change callbacks cannot be fired directly from this
    // function, due to same-thread deadlock trying to acquire mInterfaceMutex
    // twice.
    if (listener != nullptr) {
        mInitialStatusCallbackFuture = std::async(std::launch::async,
                &CameraProviderManager::ProviderInfo::notifyInitialStatusChange, this,
                listener, std::move(cachedStatus));
    }
}

CameraProviderManager::ProviderInfo::DeviceInfo* CameraProviderManager::findDeviceInfoLocked(
        const std::string& id) const {
    for (auto& provider : mProviders) {
        using hardware::hidl_version;
        IPCTransport transport = provider->getIPCTransport();
        // AIDL min version starts at major: 1 minor: 1
        hidl_version minVersion =
                (transport == IPCTransport::HIDL) ? hidl_version{3, 2} : hidl_version{1, 1} ;
        hidl_version maxVersion =
                (transport == IPCTransport::HIDL) ? hidl_version{3, 7} : hidl_version{1000, 0};

        for (auto& deviceInfo : provider->mDevices) {
            if (deviceInfo->mId == id &&
                    minVersion <= deviceInfo->mVersion && maxVersion >= deviceInfo->mVersion) {
                return deviceInfo.get();
            }
        }
    }
    return nullptr;
}

metadata_vendor_id_t CameraProviderManager::getProviderTagIdLocked(
        const std::string& id) const {
    metadata_vendor_id_t ret = CAMERA_METADATA_INVALID_VENDOR_ID;

    std::lock_guard<std::mutex> lock(mInterfaceMutex);
    for (auto& provider : mProviders) {
        for (auto& deviceInfo : provider->mDevices) {
            if (deviceInfo->mId == id) {
                return provider->mProviderTagid;
            }
        }
    }

    return ret;
}

void CameraProviderManager::ProviderInfo::DeviceInfo3::queryPhysicalCameraIds() {
    camera_metadata_entry_t entryCap;

    entryCap = mCameraCharacteristics.find(ANDROID_REQUEST_AVAILABLE_CAPABILITIES);
    for (size_t i = 0; i < entryCap.count; ++i) {
        uint8_t capability = entryCap.data.u8[i];
        if (capability == ANDROID_REQUEST_AVAILABLE_CAPABILITIES_LOGICAL_MULTI_CAMERA) {
            mIsLogicalCamera = true;
            break;
        }
    }
    if (!mIsLogicalCamera) {
        return;
    }

    camera_metadata_entry_t entryIds = mCameraCharacteristics.find(
            ANDROID_LOGICAL_MULTI_CAMERA_PHYSICAL_IDS);
    const uint8_t* ids = entryIds.data.u8;
    size_t start = 0;
    for (size_t i = 0; i < entryIds.count; ++i) {
        if (ids[i] == '\0') {
            if (start != i) {
                mPhysicalIds.push_back((const char*)ids+start);
            }
            start = i+1;
        }
    }
}

SystemCameraKind CameraProviderManager::ProviderInfo::DeviceInfo3::getSystemCameraKind() {
    camera_metadata_entry_t entryCap;
    entryCap = mCameraCharacteristics.find(ANDROID_REQUEST_AVAILABLE_CAPABILITIES);
    if (entryCap.count == 1 &&
            entryCap.data.u8[0] == ANDROID_REQUEST_AVAILABLE_CAPABILITIES_SECURE_IMAGE_DATA) {
        return SystemCameraKind::HIDDEN_SECURE_CAMERA;
    }

    // Go through the capabilities and check if it has
    // ANDROID_REQUEST_AVAILABLE_CAPABILITIES_SYSTEM_CAMERA
    for (size_t i = 0; i < entryCap.count; ++i) {
        uint8_t capability = entryCap.data.u8[i];
        if (capability == ANDROID_REQUEST_AVAILABLE_CAPABILITIES_SYSTEM_CAMERA) {
            return SystemCameraKind::SYSTEM_ONLY_CAMERA;
        }
    }
    return SystemCameraKind::PUBLIC;
}

void CameraProviderManager::ProviderInfo::DeviceInfo3::getSupportedSizes(
        const CameraMetadata& ch, uint32_t tag, android_pixel_format_t format,
        std::vector<std::tuple<size_t, size_t>> *sizes/*out*/) {
    if (sizes == nullptr) {
        return;
    }

    auto scalerDims = ch.find(tag);
    if (scalerDims.count > 0) {
        // Scaler entry contains 4 elements (format, width, height, type)
        for (size_t i = 0; i < scalerDims.count; i += 4) {
            if ((scalerDims.data.i32[i] == format) &&
                    (scalerDims.data.i32[i+3] ==
                     ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS_OUTPUT)) {
                sizes->push_back(std::make_tuple(scalerDims.data.i32[i+1],
                            scalerDims.data.i32[i+2]));
            }
        }
    }
}

void CameraProviderManager::ProviderInfo::DeviceInfo3::getSupportedDurations(
        const CameraMetadata& ch, uint32_t tag, android_pixel_format_t format,
        const std::vector<std::tuple<size_t, size_t>>& sizes,
        std::vector<int64_t> *durations/*out*/) {
    if (durations == nullptr) {
        return;
    }

    auto availableDurations = ch.find(tag);
    if (availableDurations.count > 0) {
        // Duration entry contains 4 elements (format, width, height, duration)
        for (size_t i = 0; i < availableDurations.count; i += 4) {
            for (const auto& size : sizes) {
                int64_t width = std::get<0>(size);
                int64_t height = std::get<1>(size);
                if ((availableDurations.data.i64[i] == format) &&
                        (availableDurations.data.i64[i+1] == width) &&
                        (availableDurations.data.i64[i+2] == height)) {
                    durations->push_back(availableDurations.data.i64[i+3]);
                }
            }
        }
    }
}
void CameraProviderManager::ProviderInfo::DeviceInfo3::getSupportedDynamicDepthDurations(
        const std::vector<int64_t>& depthDurations, const std::vector<int64_t>& blobDurations,
        std::vector<int64_t> *dynamicDepthDurations /*out*/) {
    if ((dynamicDepthDurations == nullptr) || (depthDurations.size() != blobDurations.size())) {
        return;
    }

    // Unfortunately there is no direct way to calculate the dynamic depth stream duration.
    // Processing time on camera service side can vary greatly depending on multiple
    // variables which are not under our control. Make a guesstimate by taking the maximum
    // corresponding duration value from depth and blob.
    auto depthDuration = depthDurations.begin();
    auto blobDuration = blobDurations.begin();
    dynamicDepthDurations->reserve(depthDurations.size());
    while ((depthDuration != depthDurations.end()) && (blobDuration != blobDurations.end())) {
        dynamicDepthDurations->push_back(std::max(*depthDuration, *blobDuration));
        depthDuration++; blobDuration++;
    }
}

void CameraProviderManager::ProviderInfo::DeviceInfo3::getSupportedDynamicDepthSizes(
        const std::vector<std::tuple<size_t, size_t>>& blobSizes,
        const std::vector<std::tuple<size_t, size_t>>& depthSizes,
        std::vector<std::tuple<size_t, size_t>> *dynamicDepthSizes /*out*/,
        std::vector<std::tuple<size_t, size_t>> *internalDepthSizes /*out*/) {
    if (dynamicDepthSizes == nullptr || internalDepthSizes == nullptr) {
        return;
    }

    // The dynamic depth spec. does not mention how close the AR ratio should be.
    // Try using something appropriate.
    float ARTolerance = kDepthARTolerance;

    for (const auto& blobSize : blobSizes) {
        float jpegAR = static_cast<float> (std::get<0>(blobSize)) /
                static_cast<float>(std::get<1>(blobSize));
        bool found = false;
        for (const auto& depthSize : depthSizes) {
            if (depthSize == blobSize) {
                internalDepthSizes->push_back(depthSize);
                found = true;
                break;
            } else {
                float depthAR = static_cast<float> (std::get<0>(depthSize)) /
                    static_cast<float>(std::get<1>(depthSize));
                if (std::fabs(jpegAR - depthAR) <= ARTolerance) {
                    internalDepthSizes->push_back(depthSize);
                    found = true;
                    break;
                }
            }
        }

        if (found) {
            dynamicDepthSizes->push_back(blobSize);
        }
    }
}

status_t CameraProviderManager::ProviderInfo::DeviceInfo3::addDynamicDepthTags(
        bool maxResolution) {
    const int32_t depthExclTag = ANDROID_DEPTH_DEPTH_IS_EXCLUSIVE;

    const int32_t scalerSizesTag =
              SessionConfigurationUtils::getAppropriateModeTag(
                      ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS, maxResolution);
    const int32_t scalerMinFrameDurationsTag =
            ANDROID_SCALER_AVAILABLE_MIN_FRAME_DURATIONS;
    const int32_t scalerStallDurationsTag =
                 SessionConfigurationUtils::getAppropriateModeTag(
                        ANDROID_SCALER_AVAILABLE_STALL_DURATIONS, maxResolution);

    const int32_t depthSizesTag =
            SessionConfigurationUtils::getAppropriateModeTag(
                    ANDROID_DEPTH_AVAILABLE_DEPTH_STREAM_CONFIGURATIONS, maxResolution);
    const int32_t depthStallDurationsTag =
            SessionConfigurationUtils::getAppropriateModeTag(
                    ANDROID_DEPTH_AVAILABLE_DEPTH_STALL_DURATIONS, maxResolution);
    const int32_t depthMinFrameDurationsTag =
            SessionConfigurationUtils::getAppropriateModeTag(
                    ANDROID_DEPTH_AVAILABLE_DEPTH_MIN_FRAME_DURATIONS, maxResolution);

    const int32_t dynamicDepthSizesTag =
            SessionConfigurationUtils::getAppropriateModeTag(
                    ANDROID_DEPTH_AVAILABLE_DYNAMIC_DEPTH_STREAM_CONFIGURATIONS, maxResolution);
    const int32_t dynamicDepthStallDurationsTag =
            SessionConfigurationUtils::getAppropriateModeTag(
                    ANDROID_DEPTH_AVAILABLE_DYNAMIC_DEPTH_STALL_DURATIONS, maxResolution);
    const int32_t dynamicDepthMinFrameDurationsTag =
            SessionConfigurationUtils::getAppropriateModeTag(
                 ANDROID_DEPTH_AVAILABLE_DYNAMIC_DEPTH_MIN_FRAME_DURATIONS, maxResolution);

    auto& c = mCameraCharacteristics;
    std::vector<std::tuple<size_t, size_t>> supportedBlobSizes, supportedDepthSizes,
            supportedDynamicDepthSizes, internalDepthSizes;
    auto chTags = c.find(ANDROID_REQUEST_AVAILABLE_CHARACTERISTICS_KEYS);
    if (chTags.count == 0) {
        ALOGE("%s: Supported camera characteristics is empty!", __FUNCTION__);
        return BAD_VALUE;
    }

    bool isDepthExclusivePresent = std::find(chTags.data.i32, chTags.data.i32 + chTags.count,
            depthExclTag) != (chTags.data.i32 + chTags.count);
    bool isDepthSizePresent = std::find(chTags.data.i32, chTags.data.i32 + chTags.count,
            depthSizesTag) != (chTags.data.i32 + chTags.count);
    if (!(isDepthExclusivePresent && isDepthSizePresent)) {
        // No depth support, nothing more to do.
        return OK;
    }

    auto depthExclusiveEntry = c.find(depthExclTag);
    if (depthExclusiveEntry.count > 0) {
        if (depthExclusiveEntry.data.u8[0] != ANDROID_DEPTH_DEPTH_IS_EXCLUSIVE_FALSE) {
            // Depth support is exclusive, nothing more to do.
            return OK;
        }
    } else {
        ALOGE("%s: Advertised depth exclusive tag but value is not present!", __FUNCTION__);
        return BAD_VALUE;
    }

    getSupportedSizes(c, scalerSizesTag, HAL_PIXEL_FORMAT_BLOB,
            &supportedBlobSizes);
    getSupportedSizes(c, depthSizesTag, HAL_PIXEL_FORMAT_Y16, &supportedDepthSizes);
    if (supportedBlobSizes.empty() || supportedDepthSizes.empty()) {
        // Nothing to do in this case.
        return OK;
    }

    getSupportedDynamicDepthSizes(supportedBlobSizes, supportedDepthSizes,
            &supportedDynamicDepthSizes, &internalDepthSizes);
    if (supportedDynamicDepthSizes.empty()) {
        // Nothing more to do.
        return OK;
    }

    std::vector<int32_t> dynamicDepthEntries;
    for (const auto& it : supportedDynamicDepthSizes) {
        int32_t entry[4] = {HAL_PIXEL_FORMAT_BLOB, static_cast<int32_t> (std::get<0>(it)),
                static_cast<int32_t> (std::get<1>(it)),
                ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS_OUTPUT };
        dynamicDepthEntries.insert(dynamicDepthEntries.end(), entry, entry + 4);
    }

    std::vector<int64_t> depthMinDurations, depthStallDurations;
    std::vector<int64_t> blobMinDurations, blobStallDurations;
    std::vector<int64_t> dynamicDepthMinDurations, dynamicDepthStallDurations;

    getSupportedDurations(c, depthMinFrameDurationsTag, HAL_PIXEL_FORMAT_Y16, internalDepthSizes,
                          &depthMinDurations);
    getSupportedDurations(c, scalerMinFrameDurationsTag, HAL_PIXEL_FORMAT_BLOB,
                          supportedDynamicDepthSizes, &blobMinDurations);
    if (blobMinDurations.empty() || depthMinDurations.empty() ||
            (depthMinDurations.size() != blobMinDurations.size())) {
        ALOGE("%s: Unexpected number of available depth min durations! %zu vs. %zu",
                __FUNCTION__, depthMinDurations.size(), blobMinDurations.size());
        return BAD_VALUE;
    }

    getSupportedDurations(c, depthStallDurationsTag, HAL_PIXEL_FORMAT_Y16, internalDepthSizes,
            &depthStallDurations);
    getSupportedDurations(c, scalerStallDurationsTag, HAL_PIXEL_FORMAT_BLOB,
            supportedDynamicDepthSizes, &blobStallDurations);
    if (blobStallDurations.empty() || depthStallDurations.empty() ||
            (depthStallDurations.size() != blobStallDurations.size())) {
        ALOGE("%s: Unexpected number of available depth stall durations! %zu vs. %zu",
                __FUNCTION__, depthStallDurations.size(), blobStallDurations.size());
        return BAD_VALUE;
    }

    getSupportedDynamicDepthDurations(depthMinDurations, blobMinDurations,
            &dynamicDepthMinDurations);
    getSupportedDynamicDepthDurations(depthStallDurations, blobStallDurations,
            &dynamicDepthStallDurations);
    if (dynamicDepthMinDurations.empty() || dynamicDepthStallDurations.empty() ||
            (dynamicDepthMinDurations.size() != dynamicDepthStallDurations.size())) {
        ALOGE("%s: Unexpected number of dynamic depth stall/min durations! %zu vs. %zu",
                __FUNCTION__, dynamicDepthMinDurations.size(), dynamicDepthStallDurations.size());
        return BAD_VALUE;
    }

    std::vector<int64_t> dynamicDepthMinDurationEntries;
    auto itDuration = dynamicDepthMinDurations.begin();
    auto itSize = supportedDynamicDepthSizes.begin();
    while (itDuration != dynamicDepthMinDurations.end()) {
        int64_t entry[4] = {HAL_PIXEL_FORMAT_BLOB, static_cast<int32_t> (std::get<0>(*itSize)),
                static_cast<int32_t> (std::get<1>(*itSize)), *itDuration};
        dynamicDepthMinDurationEntries.insert(dynamicDepthMinDurationEntries.end(), entry,
                entry + 4);
        itDuration++; itSize++;
    }

    std::vector<int64_t> dynamicDepthStallDurationEntries;
    itDuration = dynamicDepthStallDurations.begin();
    itSize = supportedDynamicDepthSizes.begin();
    while (itDuration != dynamicDepthStallDurations.end()) {
        int64_t entry[4] = {HAL_PIXEL_FORMAT_BLOB, static_cast<int32_t> (std::get<0>(*itSize)),
                static_cast<int32_t> (std::get<1>(*itSize)), *itDuration};
        dynamicDepthStallDurationEntries.insert(dynamicDepthStallDurationEntries.end(), entry,
                entry + 4);
        itDuration++; itSize++;
    }

    std::vector<int32_t> supportedChTags;
    supportedChTags.reserve(chTags.count + 3);
    supportedChTags.insert(supportedChTags.end(), chTags.data.i32,
            chTags.data.i32 + chTags.count);
    supportedChTags.push_back(dynamicDepthSizesTag);
    supportedChTags.push_back(dynamicDepthMinFrameDurationsTag);
    supportedChTags.push_back(dynamicDepthStallDurationsTag);
    c.update(dynamicDepthSizesTag, dynamicDepthEntries.data(), dynamicDepthEntries.size());
    c.update(dynamicDepthMinFrameDurationsTag, dynamicDepthMinDurationEntries.data(),
            dynamicDepthMinDurationEntries.size());
    c.update(dynamicDepthStallDurationsTag, dynamicDepthStallDurationEntries.data(),
             dynamicDepthStallDurationEntries.size());
    c.update(ANDROID_REQUEST_AVAILABLE_CHARACTERISTICS_KEYS, supportedChTags.data(),
            supportedChTags.size());

    return OK;
}

status_t CameraProviderManager::ProviderInfo::DeviceInfo3::fixupTorchStrengthTags() {
    status_t res = OK;
    auto& c = mCameraCharacteristics;
    auto flashInfoStrengthDefaultLevelEntry = c.find(ANDROID_FLASH_INFO_STRENGTH_DEFAULT_LEVEL);
    if (flashInfoStrengthDefaultLevelEntry.count == 0) {
        int32_t flashInfoStrengthDefaultLevel = 1;
        res = c.update(ANDROID_FLASH_INFO_STRENGTH_DEFAULT_LEVEL,
                &flashInfoStrengthDefaultLevel, 1);
        if (res != OK) {
            ALOGE("%s: Failed to update ANDROID_FLASH_INFO_STRENGTH_DEFAULT_LEVEL: %s (%d)",
                    __FUNCTION__,strerror(-res), res);
            return res;
        }
    }
    auto flashInfoStrengthMaximumLevelEntry = c.find(ANDROID_FLASH_INFO_STRENGTH_MAXIMUM_LEVEL);
    if (flashInfoStrengthMaximumLevelEntry.count == 0) {
        int32_t flashInfoStrengthMaximumLevel = 1;
        res = c.update(ANDROID_FLASH_INFO_STRENGTH_MAXIMUM_LEVEL,
                &flashInfoStrengthMaximumLevel, 1);
        if (res != OK) {
            ALOGE("%s: Failed to update ANDROID_FLASH_INFO_STRENGTH_MAXIMUM_LEVEL: %s (%d)",
                    __FUNCTION__,strerror(-res), res);
            return res;
        }
    }
    return res;
}

status_t CameraProviderManager::ProviderInfo::DeviceInfo3::fixupMonochromeTags() {
    status_t res = OK;
    auto& c = mCameraCharacteristics;
    sp<ProviderInfo> parentProvider = mParentProvider.promote();
    if (parentProvider == nullptr) {
        return DEAD_OBJECT;
    }
    IPCTransport ipcTransport = parentProvider->getIPCTransport();
    // Override static metadata for MONOCHROME camera with older device version
    if (ipcTransport == IPCTransport::HIDL &&
            (mVersion.get_major() == 3 && mVersion.get_minor() < 5)) {
        camera_metadata_entry cap = c.find(ANDROID_REQUEST_AVAILABLE_CAPABILITIES);
        for (size_t i = 0; i < cap.count; i++) {
            if (cap.data.u8[i] == ANDROID_REQUEST_AVAILABLE_CAPABILITIES_MONOCHROME) {
                // ANDROID_SENSOR_INFO_COLOR_FILTER_ARRANGEMENT
                uint8_t cfa = ANDROID_SENSOR_INFO_COLOR_FILTER_ARRANGEMENT_MONO;
                res = c.update(ANDROID_SENSOR_INFO_COLOR_FILTER_ARRANGEMENT, &cfa, 1);
                if (res != OK) {
                    ALOGE("%s: Failed to update COLOR_FILTER_ARRANGEMENT: %s (%d)",
                          __FUNCTION__, strerror(-res), res);
                    return res;
                }

                // ANDROID_REQUEST_AVAILABLE_CHARACTERISTICS_KEYS
                const std::vector<uint32_t> sKeys = {
                        ANDROID_SENSOR_REFERENCE_ILLUMINANT1,
                        ANDROID_SENSOR_REFERENCE_ILLUMINANT2,
                        ANDROID_SENSOR_CALIBRATION_TRANSFORM1,
                        ANDROID_SENSOR_CALIBRATION_TRANSFORM2,
                        ANDROID_SENSOR_COLOR_TRANSFORM1,
                        ANDROID_SENSOR_COLOR_TRANSFORM2,
                        ANDROID_SENSOR_FORWARD_MATRIX1,
                        ANDROID_SENSOR_FORWARD_MATRIX2,
                };
                res = removeAvailableKeys(c, sKeys,
                        ANDROID_REQUEST_AVAILABLE_CHARACTERISTICS_KEYS);
                if (res != OK) {
                    ALOGE("%s: Failed to update REQUEST_AVAILABLE_CHARACTERISTICS_KEYS: %s (%d)",
                            __FUNCTION__, strerror(-res), res);
                    return res;
                }

                // ANDROID_REQUEST_AVAILABLE_REQUEST_KEYS
                const std::vector<uint32_t> reqKeys = {
                        ANDROID_COLOR_CORRECTION_MODE,
                        ANDROID_COLOR_CORRECTION_TRANSFORM,
                        ANDROID_COLOR_CORRECTION_GAINS,
                };
                res = removeAvailableKeys(c, reqKeys, ANDROID_REQUEST_AVAILABLE_REQUEST_KEYS);
                if (res != OK) {
                    ALOGE("%s: Failed to update REQUEST_AVAILABLE_REQUEST_KEYS: %s (%d)",
                            __FUNCTION__, strerror(-res), res);
                    return res;
                }

                // ANDROID_REQUEST_AVAILABLE_RESULT_KEYS
                const std::vector<uint32_t> resKeys = {
                        ANDROID_SENSOR_GREEN_SPLIT,
                        ANDROID_SENSOR_NEUTRAL_COLOR_POINT,
                        ANDROID_COLOR_CORRECTION_MODE,
                        ANDROID_COLOR_CORRECTION_TRANSFORM,
                        ANDROID_COLOR_CORRECTION_GAINS,
                };
                res = removeAvailableKeys(c, resKeys, ANDROID_REQUEST_AVAILABLE_RESULT_KEYS);
                if (res != OK) {
                    ALOGE("%s: Failed to update REQUEST_AVAILABLE_RESULT_KEYS: %s (%d)",
                            __FUNCTION__, strerror(-res), res);
                    return res;
                }

                // ANDROID_SENSOR_BLACK_LEVEL_PATTERN
                camera_metadata_entry blEntry = c.find(ANDROID_SENSOR_BLACK_LEVEL_PATTERN);
                for (size_t j = 1; j < blEntry.count; j++) {
                    blEntry.data.i32[j] = blEntry.data.i32[0];
                }
            }
        }
    }
    return res;
}

status_t CameraProviderManager::ProviderInfo::DeviceInfo3::addRotateCropTags() {
    status_t res = OK;
    auto& c = mCameraCharacteristics;

    auto availableRotateCropEntry = c.find(ANDROID_SCALER_AVAILABLE_ROTATE_AND_CROP_MODES);
    if (availableRotateCropEntry.count == 0) {
        uint8_t defaultAvailableRotateCropEntry = ANDROID_SCALER_ROTATE_AND_CROP_NONE;
        res = c.update(ANDROID_SCALER_AVAILABLE_ROTATE_AND_CROP_MODES,
                &defaultAvailableRotateCropEntry, 1);
    }
    return res;
}

status_t CameraProviderManager::ProviderInfo::DeviceInfo3::addPreCorrectionActiveArraySize() {
    status_t res = OK;
    auto& c = mCameraCharacteristics;

    auto activeArraySize = c.find(ANDROID_SENSOR_INFO_ACTIVE_ARRAY_SIZE);
    auto preCorrectionActiveArraySize = c.find(
            ANDROID_SENSOR_INFO_PRE_CORRECTION_ACTIVE_ARRAY_SIZE);
    if (activeArraySize.count == 4 && preCorrectionActiveArraySize.count == 0) {
        std::vector<int32_t> preCorrectionArray(
                activeArraySize.data.i32, activeArraySize.data.i32+4);
        res = c.update(ANDROID_SENSOR_INFO_PRE_CORRECTION_ACTIVE_ARRAY_SIZE,
                preCorrectionArray.data(), 4);
        if (res != OK) {
            ALOGE("%s: Failed to add ANDROID_SENSOR_INFO_PRE_CORRECTION_ACTIVE_ARRAY_SIZE: %s(%d)",
                    __FUNCTION__, strerror(-res), res);
            return res;
        }
    } else {
        return res;
    }

    auto charTags = c.find(ANDROID_REQUEST_AVAILABLE_CHARACTERISTICS_KEYS);
    bool hasPreCorrectionActiveArraySize = std::find(charTags.data.i32,
            charTags.data.i32 + charTags.count,
            ANDROID_SENSOR_INFO_PRE_CORRECTION_ACTIVE_ARRAY_SIZE) !=
            (charTags.data.i32 + charTags.count);
    if (!hasPreCorrectionActiveArraySize) {
        std::vector<int32_t> supportedCharTags;
        supportedCharTags.reserve(charTags.count + 1);
        supportedCharTags.insert(supportedCharTags.end(), charTags.data.i32,
                charTags.data.i32 + charTags.count);
        supportedCharTags.push_back(ANDROID_SENSOR_INFO_PRE_CORRECTION_ACTIVE_ARRAY_SIZE);

        res = c.update(ANDROID_REQUEST_AVAILABLE_CHARACTERISTICS_KEYS, supportedCharTags.data(),
                supportedCharTags.size());
        if (res != OK) {
            ALOGE("%s: Failed to update ANDROID_REQUEST_AVAILABLE_CHARACTERISTICS_KEYS: %s(%d)",
                    __FUNCTION__, strerror(-res), res);
            return res;
        }
    }

    return res;
}

status_t CameraProviderManager::ProviderInfo::DeviceInfo3::addReadoutTimestampTag(
        bool readoutTimestampSupported) {
    status_t res = OK;
    auto& c = mCameraCharacteristics;

    auto entry = c.find(ANDROID_SENSOR_READOUT_TIMESTAMP);
    if (entry.count != 0) {
        ALOGE("%s: CameraCharacteristics must not contain ANDROID_SENSOR_READOUT_TIMESTAMP!",
                __FUNCTION__);
    }

    uint8_t readoutTimestamp = ANDROID_SENSOR_READOUT_TIMESTAMP_NOT_SUPPORTED;
    if (readoutTimestampSupported) {
        readoutTimestamp = ANDROID_SENSOR_READOUT_TIMESTAMP_HARDWARE;
    }

    res = c.update(ANDROID_SENSOR_READOUT_TIMESTAMP, &readoutTimestamp, 1);

    return res;
}

status_t CameraProviderManager::ProviderInfo::DeviceInfo3::removeAvailableKeys(
        CameraMetadata& c, const std::vector<uint32_t>& keys, uint32_t keyTag) {
    status_t res = OK;

    camera_metadata_entry keysEntry = c.find(keyTag);
    if (keysEntry.count == 0) {
        ALOGE("%s: Failed to find tag %u: %s (%d)", __FUNCTION__, keyTag, strerror(-res), res);
        return res;
    }
    std::vector<int32_t> vKeys;
    vKeys.reserve(keysEntry.count);
    for (size_t i = 0; i < keysEntry.count; i++) {
        if (std::find(keys.begin(), keys.end(), keysEntry.data.i32[i]) == keys.end()) {
            vKeys.push_back(keysEntry.data.i32[i]);
        }
    }
    res = c.update(keyTag, vKeys.data(), vKeys.size());
    return res;
}

status_t CameraProviderManager::ProviderInfo::DeviceInfo3::fillHeicStreamCombinations(
        std::vector<int32_t>* outputs,
        std::vector<int64_t>* durations,
        std::vector<int64_t>* stallDurations,
        const camera_metadata_entry& halStreamConfigs,
        const camera_metadata_entry& halStreamDurations) {
    if (outputs == nullptr || durations == nullptr || stallDurations == nullptr) {
        return BAD_VALUE;
    }

    static bool supportInMemoryTempFile =
            camera3::HeicCompositeStream::isInMemoryTempFileSupported();
    if (!supportInMemoryTempFile) {
        ALOGI("%s: No HEIC support due to absence of in memory temp file support",
                __FUNCTION__);
        return OK;
    }

    for (size_t i = 0; i < halStreamConfigs.count; i += 4) {
        int32_t format = halStreamConfigs.data.i32[i];
        // Only IMPLEMENTATION_DEFINED and YUV_888 can be used to generate HEIC
        // image.
        if (format != HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED &&
                format != HAL_PIXEL_FORMAT_YCBCR_420_888) {
            continue;
        }

        bool sizeAvail = false;
        for (size_t j = 0; j < outputs->size(); j+= 4) {
            if ((*outputs)[j+1] == halStreamConfigs.data.i32[i+1] &&
                    (*outputs)[j+2] == halStreamConfigs.data.i32[i+2]) {
                sizeAvail = true;
                break;
            }
        }
        if (sizeAvail) continue;

        int64_t stall = 0;
        bool useHeic = false;
        bool useGrid = false;
        if (camera3::HeicCompositeStream::isSizeSupportedByHeifEncoder(
                halStreamConfigs.data.i32[i+1], halStreamConfigs.data.i32[i+2],
                &useHeic, &useGrid, &stall)) {
            if (useGrid != (format == HAL_PIXEL_FORMAT_YCBCR_420_888)) {
                continue;
            }

            // HEIC configuration
            int32_t config[] = {HAL_PIXEL_FORMAT_BLOB, halStreamConfigs.data.i32[i+1],
                    halStreamConfigs.data.i32[i+2], 0 /*isInput*/};
            outputs->insert(outputs->end(), config, config + 4);

            // HEIC minFrameDuration
            for (size_t j = 0; j < halStreamDurations.count; j += 4) {
                if (halStreamDurations.data.i64[j] == format &&
                        halStreamDurations.data.i64[j+1] == halStreamConfigs.data.i32[i+1] &&
                        halStreamDurations.data.i64[j+2] == halStreamConfigs.data.i32[i+2]) {
                    int64_t duration[] = {HAL_PIXEL_FORMAT_BLOB, halStreamConfigs.data.i32[i+1],
                            halStreamConfigs.data.i32[i+2], halStreamDurations.data.i64[j+3]};
                    durations->insert(durations->end(), duration, duration+4);
                    break;
                }
            }

            // HEIC stallDuration
            int64_t stallDuration[] = {HAL_PIXEL_FORMAT_BLOB, halStreamConfigs.data.i32[i+1],
                    halStreamConfigs.data.i32[i+2], stall};
            stallDurations->insert(stallDurations->end(), stallDuration, stallDuration+4);
        }
    }
    return OK;
}

status_t CameraProviderManager::ProviderInfo::DeviceInfo3::deriveHeicTags(bool maxResolution) {
    int32_t scalerStreamSizesTag =
            SessionConfigurationUtils::getAppropriateModeTag(
                    ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS, maxResolution);
    int32_t scalerMinFrameDurationsTag =
            SessionConfigurationUtils::getAppropriateModeTag(
                    ANDROID_SCALER_AVAILABLE_MIN_FRAME_DURATIONS, maxResolution);

    int32_t heicStreamSizesTag =
            SessionConfigurationUtils::getAppropriateModeTag(
                    ANDROID_HEIC_AVAILABLE_HEIC_STREAM_CONFIGURATIONS, maxResolution);
    int32_t heicMinFrameDurationsTag =
            SessionConfigurationUtils::getAppropriateModeTag(
                    ANDROID_HEIC_AVAILABLE_HEIC_MIN_FRAME_DURATIONS, maxResolution);
    int32_t heicStallDurationsTag =
            SessionConfigurationUtils::getAppropriateModeTag(
                    ANDROID_HEIC_AVAILABLE_HEIC_STALL_DURATIONS, maxResolution);

    auto& c = mCameraCharacteristics;

    camera_metadata_entry halHeicSupport = c.find(ANDROID_HEIC_INFO_SUPPORTED);
    if (halHeicSupport.count > 1) {
        ALOGE("%s: Invalid entry count %zu for ANDROID_HEIC_INFO_SUPPORTED",
                __FUNCTION__, halHeicSupport.count);
        return BAD_VALUE;
    } else if (halHeicSupport.count == 0 ||
            halHeicSupport.data.u8[0] == ANDROID_HEIC_INFO_SUPPORTED_FALSE) {
        // Camera HAL doesn't support mandatory stream combinations for HEIC.
        return OK;
    }

    camera_metadata_entry maxJpegAppsSegments =
            c.find(ANDROID_HEIC_INFO_MAX_JPEG_APP_SEGMENTS_COUNT);
    if (maxJpegAppsSegments.count != 1 || maxJpegAppsSegments.data.u8[0] == 0 ||
            maxJpegAppsSegments.data.u8[0] > 16) {
        ALOGE("%s: ANDROID_HEIC_INFO_MAX_JPEG_APP_SEGMENTS_COUNT must be within [1, 16]",
                __FUNCTION__);
        return BAD_VALUE;
    }

    // Populate HEIC output configurations and its related min frame duration
    // and stall duration.
    std::vector<int32_t> heicOutputs;
    std::vector<int64_t> heicDurations;
    std::vector<int64_t> heicStallDurations;

    camera_metadata_entry halStreamConfigs = c.find(scalerStreamSizesTag);
    camera_metadata_entry minFrameDurations = c.find(scalerMinFrameDurationsTag);

    status_t res = fillHeicStreamCombinations(&heicOutputs, &heicDurations, &heicStallDurations,
            halStreamConfigs, minFrameDurations);
    if (res != OK) {
        ALOGE("%s: Failed to fill HEIC stream combinations: %s (%d)", __FUNCTION__,
                strerror(-res), res);
        return res;
    }

    c.update(heicStreamSizesTag, heicOutputs.data(), heicOutputs.size());
    c.update(heicMinFrameDurationsTag, heicDurations.data(), heicDurations.size());
    c.update(heicStallDurationsTag, heicStallDurations.data(), heicStallDurations.size());

    return OK;
}

bool CameraProviderManager::isLogicalCameraLocked(const std::string& id,
        std::vector<std::string>* physicalCameraIds) {
    auto deviceInfo = findDeviceInfoLocked(id);
    if (deviceInfo == nullptr) return false;

    if (deviceInfo->mIsLogicalCamera && physicalCameraIds != nullptr) {
        *physicalCameraIds = deviceInfo->mPhysicalIds;
    }
    return deviceInfo->mIsLogicalCamera;
}

bool CameraProviderManager::isLogicalCamera(const std::string& id,
        std::vector<std::string>* physicalCameraIds) {
    std::lock_guard<std::mutex> lock(mInterfaceMutex);
    return isLogicalCameraLocked(id, physicalCameraIds);
}

status_t CameraProviderManager::getSystemCameraKind(const std::string& id,
        SystemCameraKind *kind) const {
    std::lock_guard<std::mutex> lock(mInterfaceMutex);
    return getSystemCameraKindLocked(id, kind);
}

status_t CameraProviderManager::getSystemCameraKindLocked(const std::string& id,
        SystemCameraKind *kind) const {
    auto deviceInfo = findDeviceInfoLocked(id);
    if (deviceInfo != nullptr) {
        *kind = deviceInfo->mSystemCameraKind;
        return OK;
    }
    // If this is a hidden physical camera, we should return what kind of
    // camera the enclosing logical camera is.
    auto isHiddenAndParent = isHiddenPhysicalCameraInternal(id);
    if (isHiddenAndParent.first) {
        LOG_ALWAYS_FATAL_IF(id == isHiddenAndParent.second->mId,
                "%s: hidden physical camera id %s and enclosing logical camera id %s are the same",
                __FUNCTION__, id.c_str(), isHiddenAndParent.second->mId.c_str());
        return getSystemCameraKindLocked(isHiddenAndParent.second->mId, kind);
    }
    // Neither a hidden physical camera nor a logical camera
    return NAME_NOT_FOUND;
}

bool CameraProviderManager::isHiddenPhysicalCamera(const std::string& cameraId) const {
    std::lock_guard<std::mutex> lock(mInterfaceMutex);
    return isHiddenPhysicalCameraInternal(cameraId).first;
}

status_t CameraProviderManager::filterSmallJpegSizes(const std::string& cameraId) {
    std::lock_guard<std::mutex> lock(mInterfaceMutex);
    for (auto& provider : mProviders) {
        for (auto& deviceInfo : provider->mDevices) {
            if (deviceInfo->mId == cameraId) {
                return deviceInfo->filterSmallJpegSizes();
            }
        }
    }
    return NAME_NOT_FOUND;
}

std::pair<bool, CameraProviderManager::ProviderInfo::DeviceInfo *>
CameraProviderManager::isHiddenPhysicalCameraInternal(const std::string& cameraId) const {
    auto falseRet = std::make_pair(false, nullptr);
    for (auto& provider : mProviders) {
        for (auto& deviceInfo : provider->mDevices) {
            if (deviceInfo->mId == cameraId) {
                // cameraId is found in public camera IDs advertised by the
                // provider.
                return falseRet;
            }
        }
    }

    for (auto& provider : mProviders) {
        IPCTransport transport = provider->getIPCTransport();
        for (auto& deviceInfo : provider->mDevices) {
            std::vector<std::string> physicalIds;
            if (deviceInfo->mIsLogicalCamera) {
                if (std::find(deviceInfo->mPhysicalIds.begin(), deviceInfo->mPhysicalIds.end(),
                        cameraId) != deviceInfo->mPhysicalIds.end()) {
                    int deviceVersion = HARDWARE_DEVICE_API_VERSION(
                            deviceInfo->mVersion.get_major(), deviceInfo->mVersion.get_minor());
                    if (transport == IPCTransport::HIDL &&
                            deviceVersion < CAMERA_DEVICE_API_VERSION_3_5) {
                        ALOGE("%s: Wrong deviceVersion %x for hiddenPhysicalCameraId %s",
                                __FUNCTION__, deviceVersion, cameraId.c_str());
                        return falseRet;
                    } else {
                        return std::make_pair(true, deviceInfo.get());
                    }
                }
            }
        }
    }

    return falseRet;
}

status_t CameraProviderManager::tryToInitializeAidlProviderLocked(
        const std::string& providerName, const sp<ProviderInfo>& providerInfo) {
    using aidl::android::hardware::camera::provider::ICameraProvider;
    std::shared_ptr<ICameraProvider> interface =
            ICameraProvider::fromBinder(ndk::SpAIBinder(
                    AServiceManager_getService(providerName.c_str())));

    if (interface == nullptr) {
        ALOGW("%s: AIDL Camera provider HAL '%s' is not actually available", __FUNCTION__,
                providerName.c_str());
        return BAD_VALUE;
    }

    AidlProviderInfo *aidlProviderInfo = static_cast<AidlProviderInfo *>(providerInfo.get());
    return aidlProviderInfo->initializeAidlProvider(interface, mDeviceState);
}

status_t CameraProviderManager::tryToInitializeHidlProviderLocked(
        const std::string& providerName, const sp<ProviderInfo>& providerInfo) {
    sp<provider::V2_4::ICameraProvider> interface;
    interface = mHidlServiceProxy->tryGetService(providerName);

    if (interface == nullptr) {
        // The interface may not be started yet. In that case, this is not a
        // fatal error.
        ALOGW("%s: HIDL Camera provider HAL '%s' is not actually available", __FUNCTION__,
                providerName.c_str());
        return BAD_VALUE;
    }

    HidlProviderInfo *hidlProviderInfo = static_cast<HidlProviderInfo *>(providerInfo.get());
    return hidlProviderInfo->initializeHidlProvider(interface, mDeviceState);
}

status_t CameraProviderManager::addAidlProviderLocked(const std::string& newProvider) {
    // Several camera provider instances can be temporarily present.
    // Defer initialization of a new instance until the older instance is properly removed.
    auto providerInstance = newProvider + "-" + std::to_string(mProviderInstanceId);
    bool providerPresent = false;
    bool preexisting =
            (mAidlProviderWithBinders.find(newProvider) != mAidlProviderWithBinders.end());

    // We need to use the extracted provider name here since 'newProvider' has
    // the fully qualified name of the provider service in case of AIDL. We want
    // just instance name.
    using aidl::android::hardware::camera::provider::ICameraProvider;
    std::string extractedProviderName =
            newProvider.substr(std::string(ICameraProvider::descriptor).size() + 1);
    for (const auto& providerInfo : mProviders) {
        if (providerInfo->mProviderName == extractedProviderName) {
            ALOGW("%s: Camera provider HAL with name '%s' already registered",
                    __FUNCTION__, newProvider.c_str());
            // Do not add new instances for lazy HAL external provider or aidl
            // binders previously seen.
            if (preexisting || providerInfo->isExternalLazyHAL()) {
                return ALREADY_EXISTS;
            } else {
                ALOGW("%s: The new provider instance will get initialized immediately after the"
                        " currently present instance is removed!", __FUNCTION__);
                providerPresent = true;
                break;
            }
        }
    }

    sp<AidlProviderInfo> providerInfo =
            new AidlProviderInfo(extractedProviderName, providerInstance, this);

    if (!providerPresent) {
        status_t res = tryToInitializeAidlProviderLocked(newProvider, providerInfo);
        if (res != OK) {
            return res;
        }
        mAidlProviderWithBinders.emplace(newProvider);
    }

    mProviders.push_back(providerInfo);
    mProviderInstanceId++;

    return OK;
}

status_t CameraProviderManager::addHidlProviderLocked(const std::string& newProvider,
        bool preexisting) {
    // Several camera provider instances can be temporarily present.
    // Defer initialization of a new instance until the older instance is properly removed.
    auto providerInstance = newProvider + "-" + std::to_string(mProviderInstanceId);
    bool providerPresent = false;
    for (const auto& providerInfo : mProviders) {
        if (providerInfo->mProviderName == newProvider) {
            ALOGW("%s: Camera provider HAL with name '%s' already registered",
                    __FUNCTION__, newProvider.c_str());
            // Do not add new instances for lazy HAL external provider
            if (preexisting || providerInfo->isExternalLazyHAL()) {
                return ALREADY_EXISTS;
            } else {
                ALOGW("%s: The new provider instance will get initialized immediately after the"
                        " currently present instance is removed!", __FUNCTION__);
                providerPresent = true;
                break;
            }
        }
    }

    sp<HidlProviderInfo> providerInfo = new HidlProviderInfo(newProvider, providerInstance, this);
    if (!providerPresent) {
        status_t res = tryToInitializeHidlProviderLocked(newProvider, providerInfo);
        if (res != OK) {
            return res;
        }
    }

    mProviders.push_back(providerInfo);
    mProviderInstanceId++;

    return OK;
}

status_t CameraProviderManager::removeProvider(const std::string& provider) {
    std::lock_guard<std::mutex> providerLock(mProviderLifecycleLock);
    std::unique_lock<std::mutex> lock(mInterfaceMutex);
    std::vector<String8> removedDeviceIds;
    status_t res = NAME_NOT_FOUND;
    std::string removedProviderName;
    for (auto it = mProviders.begin(); it != mProviders.end(); it++) {
        if ((*it)->mProviderInstance == provider) {
            removedDeviceIds.reserve((*it)->mDevices.size());
            for (auto& deviceInfo : (*it)->mDevices) {
                removedDeviceIds.push_back(String8(deviceInfo->mId.c_str()));
            }
            removedProviderName = (*it)->mProviderName;
            mProviders.erase(it);
            res = OK;
            break;
        }
    }
    if (res != OK) {
        ALOGW("%s: Camera provider HAL with name '%s' is not registered", __FUNCTION__,
                provider.c_str());
    } else {
        // Check if there are any newer camera instances from the same provider and try to
        // initialize.
        for (const auto& providerInfo : mProviders) {
            if (providerInfo->mProviderName == removedProviderName) {
                IPCTransport providerTransport = providerInfo->getIPCTransport();
                std::string removedAidlProviderName = getFullAidlProviderName(removedProviderName);
                switch(providerTransport) {
                    case IPCTransport::HIDL:
                        return tryToInitializeHidlProviderLocked(removedProviderName, providerInfo);
                    case IPCTransport::AIDL:
                        return tryToInitializeAidlProviderLocked(removedAidlProviderName,
                                providerInfo);
                    default:
                        ALOGE("%s Unsupported Transport %d", __FUNCTION__, providerTransport);
                }
            }
        }

        // Inform camera service of loss of presence for all the devices from this provider,
        // without lock held for reentrancy
        sp<StatusListener> listener = getStatusListener();
        if (listener != nullptr) {
            lock.unlock();
            for (auto& id : removedDeviceIds) {
                listener->onDeviceStatusChanged(id, CameraDeviceStatus::NOT_PRESENT);
            }
            lock.lock();
        }

    }
    return res;
}

sp<CameraProviderManager::StatusListener> CameraProviderManager::getStatusListener() const {
    return mListener.promote();
}
/**** Methods for ProviderInfo ****/


CameraProviderManager::ProviderInfo::ProviderInfo(
        const std::string &providerName,
        const std::string &providerInstance,
        CameraProviderManager *manager) :
        mProviderName(providerName),
        mProviderInstance(providerInstance),
        mProviderTagid(generateVendorTagId(providerName)),
        mUniqueDeviceCount(0),
        mManager(manager) {
    (void) mManager;
}

const std::string& CameraProviderManager::ProviderInfo::getType() const {
    return mType;
}

status_t CameraProviderManager::ProviderInfo::addDevice(
        const std::string& name, CameraDeviceStatus initialStatus,
        /*out*/ std::string* parsedId) {

    ALOGI("Enumerating new camera device: %s", name.c_str());

    uint16_t major, minor;
    std::string type, id;
    IPCTransport transport = getIPCTransport();

    status_t res = parseDeviceName(name, &major, &minor, &type, &id);
    if (res != OK) {
        return res;
    }

    if (type != mType) {
        ALOGE("%s: Device type %s does not match provider type %s", __FUNCTION__,
                type.c_str(), mType.c_str());
        return BAD_VALUE;
    }
    if (mManager->isValidDeviceLocked(id, major, transport)) {
        ALOGE("%s: Device %s: ID %s is already in use for device major version %d", __FUNCTION__,
                name.c_str(), id.c_str(), major);
        return BAD_VALUE;
    }

    std::unique_ptr<DeviceInfo> deviceInfo;
    switch (transport) {
        case IPCTransport::HIDL:
            switch (major) {
                case 3:
                    break;
                default:
                    ALOGE("%s: Device %s: Unsupported HIDL device HAL major version %d:",
                          __FUNCTION__,  name.c_str(), major);
                    return BAD_VALUE;
            }
            break;
        case IPCTransport::AIDL:
            if (major != 1) {
                ALOGE("%s: Device %s: Unsupported AIDL device HAL major version %d:", __FUNCTION__,
                        name.c_str(), major);
                return BAD_VALUE;
            }
            break;
        default:
            ALOGE("%s Invalid transport %d", __FUNCTION__, transport);
            return BAD_VALUE;
    }

    deviceInfo = initializeDeviceInfo(name, mProviderTagid, id, minor);
    if (deviceInfo == nullptr) return BAD_VALUE;
    deviceInfo->notifyDeviceStateChange(getDeviceState());
    deviceInfo->mStatus = initialStatus;
    bool isAPI1Compatible = deviceInfo->isAPI1Compatible();

    mDevices.push_back(std::move(deviceInfo));

    mUniqueCameraIds.insert(id);
    if (isAPI1Compatible) {
        // addDevice can be called more than once for the same camera id if HAL
        // supports openLegacy.
        if (std::find(mUniqueAPI1CompatibleCameraIds.begin(), mUniqueAPI1CompatibleCameraIds.end(),
                id) == mUniqueAPI1CompatibleCameraIds.end()) {
            mUniqueAPI1CompatibleCameraIds.push_back(id);
        }
    }

    if (parsedId != nullptr) {
        *parsedId = id;
    }
    return OK;
}

void CameraProviderManager::ProviderInfo::removeDevice(std::string id) {
    for (auto it = mDevices.begin(); it != mDevices.end(); it++) {
        if ((*it)->mId == id) {
            mUniqueCameraIds.erase(id);
            if ((*it)->isAPI1Compatible()) {
                mUniqueAPI1CompatibleCameraIds.erase(std::remove(
                    mUniqueAPI1CompatibleCameraIds.begin(),
                    mUniqueAPI1CompatibleCameraIds.end(), id));
            }

            // Remove reference to camera provider to avoid pointer leak when
            // unplugging external camera while in use with lazy HALs
            mManager->removeRef(DeviceMode::CAMERA, id);
            mManager->removeRef(DeviceMode::TORCH, id);

            mDevices.erase(it);
            break;
        }
    }
}

void CameraProviderManager::ProviderInfo::removeAllDevices() {
    std::lock_guard<std::mutex> lock(mLock);

    auto itDevices = mDevices.begin();
    while (itDevices != mDevices.end()) {
        std::string id = (*itDevices)->mId;
        std::string deviceName = (*itDevices)->mName;
        removeDevice(id);
        // device was removed, reset iterator
        itDevices = mDevices.begin();

        //notify CameraService of status change
        sp<StatusListener> listener = mManager->getStatusListener();
        if (listener != nullptr) {
            mLock.unlock();
            ALOGV("%s: notify device not_present: %s",
                  __FUNCTION__,
                  deviceName.c_str());
            listener->onDeviceStatusChanged(String8(id.c_str()),
                                            CameraDeviceStatus::NOT_PRESENT);
            mLock.lock();
        }
    }
}

bool CameraProviderManager::ProviderInfo::isExternalLazyHAL() const {
    return kEnableLazyHal && (mProviderName == kExternalProviderName);
}

status_t CameraProviderManager::ProviderInfo::dump(int fd, const Vector<String16>&) const {
    dprintf(fd, "== Camera Provider HAL %s (v2.%d, %s) static info: %zu devices: ==\n",
            mProviderInstance.c_str(),
            mMinorVersion,
            mIsRemote ? "remote" : "passthrough",
            mDevices.size());

    for (auto& device : mDevices) {
        dprintf(fd, "== Camera HAL device %s (v%d.%d) static information: ==\n", device->mName.c_str(),
                device->mVersion.get_major(), device->mVersion.get_minor());
        dprintf(fd, "  Resource cost: %d\n", device->mResourceCost.resourceCost);
        if (device->mResourceCost.conflictingDevices.size() == 0) {
            dprintf(fd, "  Conflicting devices: None\n");
        } else {
            dprintf(fd, "  Conflicting devices:\n");
            for (size_t i = 0; i < device->mResourceCost.conflictingDevices.size(); i++) {
                dprintf(fd, "    %s\n",
                        device->mResourceCost.conflictingDevices[i].c_str());
            }
        }
        dprintf(fd, "  API1 info:\n");
        dprintf(fd, "    Has a flash unit: %s\n",
                device->hasFlashUnit() ? "true" : "false");
        hardware::CameraInfo info;
        status_t res = device->getCameraInfo(&info);
        if (res != OK) {
            dprintf(fd, "   <Error reading camera info: %s (%d)>\n",
                    strerror(-res), res);
        } else {
            dprintf(fd, "    Facing: %s\n",
                    info.facing == hardware::CAMERA_FACING_BACK ? "Back" : "Front");
            dprintf(fd, "    Orientation: %d\n", info.orientation);
        }
        CameraMetadata info2;
        res = device->getCameraCharacteristics(true /*overrideForPerfClass*/, &info2);
        if (res == INVALID_OPERATION) {
            dprintf(fd, "  API2 not directly supported\n");
        } else if (res != OK) {
            dprintf(fd, "  <Error reading camera characteristics: %s (%d)>\n",
                    strerror(-res), res);
        } else {
            dprintf(fd, "  API2 camera characteristics:\n");
            info2.dump(fd, /*verbosity*/ 2, /*indentation*/ 4);
        }

        // Dump characteristics of non-standalone physical camera
        if (device->mIsLogicalCamera) {
            for (auto& id : device->mPhysicalIds) {
                // Skip if physical id is an independent camera
                if (std::find(mProviderPublicCameraIds.begin(), mProviderPublicCameraIds.end(), id)
                        != mProviderPublicCameraIds.end()) {
                    continue;
                }

                CameraMetadata physicalInfo;
                status_t status = device->getPhysicalCameraCharacteristics(id, &physicalInfo);
                if (status == OK) {
                    dprintf(fd, "  Physical camera %s characteristics:\n", id.c_str());
                    physicalInfo.dump(fd, /*verbosity*/ 2, /*indentation*/ 4);
                }
            }
        }

        dprintf(fd, "== Camera HAL device %s (v%d.%d) dumpState: ==\n", device->mName.c_str(),
                device->mVersion.get_major(), device->mVersion.get_minor());
        res = device->dumpState(fd);
        if (res != OK) {
            dprintf(fd, "   <Error dumping device %s state: %s (%d)>\n",
                    device->mName.c_str(), strerror(-res), res);
        }
    }
    return OK;
}

std::vector<std::unordered_set<std::string>>
CameraProviderManager::ProviderInfo::getConcurrentCameraIdCombinations() {
    std::lock_guard<std::mutex> lock(mLock);
    return mConcurrentCameraIdCombinations;
}

void CameraProviderManager::ProviderInfo::cameraDeviceStatusChangeInternal(
        const std::string& cameraDeviceName, CameraDeviceStatus newStatus) {
    sp<StatusListener> listener;
    std::string id;
    std::lock_guard<std::mutex> lock(mInitLock);
    CameraDeviceStatus internalNewStatus = newStatus;
    if (!mInitialized) {
        mCachedStatus.emplace_back(false /*isPhysicalCameraStatus*/,
                cameraDeviceName.c_str(), std::string().c_str(),
                internalNewStatus);
        return;
    }

    {
        std::lock_guard<std::mutex> lock(mLock);
        if (OK != cameraDeviceStatusChangeLocked(&id, cameraDeviceName, newStatus)) {
            return;
        }
        listener = mManager->getStatusListener();
    }

    // Call without lock held to allow reentrancy into provider manager
    if (listener != nullptr) {
        listener->onDeviceStatusChanged(String8(id.c_str()), internalNewStatus);
    }
}

status_t CameraProviderManager::ProviderInfo::cameraDeviceStatusChangeLocked(
        std::string* id, const std::string& cameraDeviceName,
        CameraDeviceStatus newStatus) {
    bool known = false;
    std::string cameraId;
    for (auto& deviceInfo : mDevices) {
        if (deviceInfo->mName == cameraDeviceName) {
            Mutex::Autolock l(deviceInfo->mDeviceAvailableLock);
            ALOGI("Camera device %s status is now %s, was %s", cameraDeviceName.c_str(),
                    FrameworkDeviceStatusToString(newStatus),
                    FrameworkDeviceStatusToString(deviceInfo->mStatus));
            deviceInfo->mStatus = newStatus;
            // TODO: Handle device removal (NOT_PRESENT)
            cameraId = deviceInfo->mId;
            known = true;
            deviceInfo->mIsDeviceAvailable =
                (newStatus == CameraDeviceStatus::PRESENT);
            deviceInfo->mDeviceAvailableSignal.signal();
            break;
        }
    }
    // Previously unseen device; status must not be NOT_PRESENT
    if (!known) {
        if (newStatus == CameraDeviceStatus::NOT_PRESENT) {
            ALOGW("Camera provider %s says an unknown camera device %s is not present. Curious.",
                mProviderName.c_str(), cameraDeviceName.c_str());
            return BAD_VALUE;
        }
        addDevice(cameraDeviceName, newStatus, &cameraId);
    } else if (newStatus == CameraDeviceStatus::NOT_PRESENT) {
        removeDevice(cameraId);
    } else if (isExternalLazyHAL()) {
        // Do not notify CameraService for PRESENT->PRESENT (lazy HAL restart)
        // because NOT_AVAILABLE is set on CameraService::connect and a PRESENT
        // notif. would overwrite it
        return BAD_VALUE;
    }

    if (reCacheConcurrentStreamingCameraIdsLocked() != OK) {
        ALOGE("%s: CameraProvider %s could not re-cache concurrent streaming camera id list ",
                  __FUNCTION__, mProviderName.c_str());
    }
    *id = cameraId;
    return OK;
}

void CameraProviderManager::ProviderInfo::physicalCameraDeviceStatusChangeInternal(
        const std::string& cameraDeviceName,
        const std::string& physicalCameraDeviceName,
        CameraDeviceStatus newStatus) {
    sp<StatusListener> listener;
    std::string id;
    std::string physicalId;
    std::lock_guard<std::mutex> lock(mInitLock);
    if (!mInitialized) {
        mCachedStatus.emplace_back(true /*isPhysicalCameraStatus*/, cameraDeviceName,
                physicalCameraDeviceName, newStatus);
        return;
    }

    {
        std::lock_guard<std::mutex> lock(mLock);

        if (OK != physicalCameraDeviceStatusChangeLocked(&id, &physicalId, cameraDeviceName,
                physicalCameraDeviceName, newStatus)) {
            return;
        }

        listener = mManager->getStatusListener();
    }
    // Call without lock held to allow reentrancy into provider manager
    if (listener != nullptr) {
        listener->onDeviceStatusChanged(String8(id.c_str()),
                String8(physicalId.c_str()), newStatus);
    }
    return;
}

status_t CameraProviderManager::ProviderInfo::physicalCameraDeviceStatusChangeLocked(
            std::string* id, std::string* physicalId,
            const std::string& cameraDeviceName,
            const std::string& physicalCameraDeviceName,
            CameraDeviceStatus newStatus) {
    bool known = false;
    std::string cameraId;
    for (auto& deviceInfo : mDevices) {
        if (deviceInfo->mName == cameraDeviceName) {
            cameraId = deviceInfo->mId;
            if (!deviceInfo->mIsLogicalCamera) {
                ALOGE("%s: Invalid combination of camera id %s, physical id %s",
                        __FUNCTION__, cameraId.c_str(), physicalCameraDeviceName.c_str());
                return BAD_VALUE;
            }
            if (std::find(deviceInfo->mPhysicalIds.begin(), deviceInfo->mPhysicalIds.end(),
                    physicalCameraDeviceName) == deviceInfo->mPhysicalIds.end()) {
                ALOGE("%s: Invalid combination of camera id %s, physical id %s",
                        __FUNCTION__, cameraId.c_str(), physicalCameraDeviceName.c_str());
                return BAD_VALUE;
            }
            ALOGI("Camera device %s physical device %s status is now %s",
                    cameraDeviceName.c_str(), physicalCameraDeviceName.c_str(),
                    FrameworkDeviceStatusToString(newStatus));
            known = true;
            break;
        }
    }
    // Previously unseen device; status must not be NOT_PRESENT
    if (!known) {
        ALOGW("Camera provider %s says an unknown camera device %s-%s is not present. Curious.",
                mProviderName.c_str(), cameraDeviceName.c_str(),
                physicalCameraDeviceName.c_str());
        return BAD_VALUE;
    }

    *id = cameraId;
    *physicalId = physicalCameraDeviceName.c_str();
    return OK;
}

void CameraProviderManager::ProviderInfo::torchModeStatusChangeInternal(
        const std::string& cameraDeviceName,
        TorchModeStatus newStatus) {
    sp<StatusListener> listener;
    SystemCameraKind systemCameraKind = SystemCameraKind::PUBLIC;
    std::string id;
    bool known = false;
    {
        // Hold mLock for accessing mDevices
        std::lock_guard<std::mutex> lock(mLock);
        for (auto& deviceInfo : mDevices) {
            if (deviceInfo->mName == cameraDeviceName) {
                ALOGI("Camera device %s torch status is now %s", cameraDeviceName.c_str(),
                        FrameworkTorchStatusToString(newStatus));
                id = deviceInfo->mId;
                known = true;
                systemCameraKind = deviceInfo->mSystemCameraKind;
                if (TorchModeStatus::AVAILABLE_ON != newStatus) {
                    mManager->removeRef(CameraProviderManager::DeviceMode::TORCH, id);
                }
                break;
            }
        }
        if (!known) {
            ALOGW("Camera provider %s says an unknown camera %s now has torch status %d. Curious.",
                    mProviderName.c_str(), cameraDeviceName.c_str(), newStatus);
            return;
        }
        // no lock needed since listener is set up only once during
        // CameraProviderManager initialization and then never changed till it is
        // destructed.
        listener = mManager->getStatusListener();
     }
    // Call without lock held to allow reentrancy into provider manager
    // The problem with holding mLock here is that we
    // might be limiting re-entrancy : CameraService::onTorchStatusChanged calls
    // back into CameraProviderManager which might try to hold mLock again (eg:
    // findDeviceInfo, which should be holding mLock while iterating through
    // each provider's devices).
    if (listener != nullptr) {
        listener->onTorchStatusChanged(String8(id.c_str()), newStatus, systemCameraKind);
    }
    return;
}

void CameraProviderManager::ProviderInfo::notifyDeviceInfoStateChangeLocked(
        int64_t newDeviceState) {
    std::lock_guard<std::mutex> lock(mLock);
    for (auto it = mDevices.begin(); it != mDevices.end(); it++) {
        (*it)->notifyDeviceStateChange(newDeviceState);
    }
}

void CameraProviderManager::ProviderInfo::notifyInitialStatusChange(
        sp<StatusListener> listener,
        std::unique_ptr<std::vector<CameraStatusInfoT>> cachedStatus) {
    for (auto& statusInfo : *cachedStatus) {
        if (statusInfo.isPhysicalCameraStatus) {
            listener->onDeviceStatusChanged(String8(statusInfo.cameraId.c_str()),
                    String8(statusInfo.physicalCameraId.c_str()), statusInfo.status);
        } else {
            listener->onDeviceStatusChanged(
                    String8(statusInfo.cameraId.c_str()), statusInfo.status);
        }
    }
}

CameraProviderManager::ProviderInfo::DeviceInfo3::DeviceInfo3(const std::string& name,
        const metadata_vendor_id_t tagId, const std::string &id,
        uint16_t minorVersion,
        const CameraResourceCost& resourceCost,
        sp<ProviderInfo> parentProvider,
        const std::vector<std::string>& publicCameraIds) :
        DeviceInfo(name, tagId, id, hardware::hidl_version{3, minorVersion},
                   publicCameraIds, resourceCost, parentProvider) { }

void CameraProviderManager::ProviderInfo::DeviceInfo3::notifyDeviceStateChange(int64_t newState) {
    if (!mDeviceStateOrientationMap.empty() &&
            (mDeviceStateOrientationMap.find(newState) != mDeviceStateOrientationMap.end())) {
        mCameraCharacteristics.update(ANDROID_SENSOR_ORIENTATION,
                &mDeviceStateOrientationMap[newState], 1);
    }
}

status_t CameraProviderManager::ProviderInfo::DeviceInfo3::getCameraInfo(
        hardware::CameraInfo *info) const {
    if (info == nullptr) return BAD_VALUE;

    camera_metadata_ro_entry facing =
            mCameraCharacteristics.find(ANDROID_LENS_FACING);
    if (facing.count == 1) {
        switch (facing.data.u8[0]) {
            case ANDROID_LENS_FACING_BACK:
                info->facing = hardware::CAMERA_FACING_BACK;
                break;
            case ANDROID_LENS_FACING_EXTERNAL:
                // Map external to front for legacy API
            case ANDROID_LENS_FACING_FRONT:
                info->facing = hardware::CAMERA_FACING_FRONT;
                break;
        }
    } else {
        ALOGE("%s: Unable to find android.lens.facing static metadata", __FUNCTION__);
        return NAME_NOT_FOUND;
    }

    camera_metadata_ro_entry orientation =
            mCameraCharacteristics.find(ANDROID_SENSOR_ORIENTATION);
    if (orientation.count == 1) {
        info->orientation = orientation.data.i32[0];
    } else {
        ALOGE("%s: Unable to find android.sensor.orientation static metadata", __FUNCTION__);
        return NAME_NOT_FOUND;
    }

    return OK;
}
bool CameraProviderManager::ProviderInfo::DeviceInfo3::isAPI1Compatible() const {
    // Do not advertise NIR cameras to API1 camera app.
    camera_metadata_ro_entry cfa = mCameraCharacteristics.find(
            ANDROID_SENSOR_INFO_COLOR_FILTER_ARRANGEMENT);
    if (cfa.count == 1 && cfa.data.u8[0] == ANDROID_SENSOR_INFO_COLOR_FILTER_ARRANGEMENT_NIR) {
        return false;
    }

    bool isBackwardCompatible = false;
    camera_metadata_ro_entry_t caps = mCameraCharacteristics.find(
            ANDROID_REQUEST_AVAILABLE_CAPABILITIES);
    for (size_t i = 0; i < caps.count; i++) {
        if (caps.data.u8[i] ==
                ANDROID_REQUEST_AVAILABLE_CAPABILITIES_BACKWARD_COMPATIBLE) {
            isBackwardCompatible = true;
            break;
        }
    }

    return isBackwardCompatible;
}

status_t CameraProviderManager::ProviderInfo::DeviceInfo3::getCameraCharacteristics(
        bool overrideForPerfClass, CameraMetadata *characteristics) const {
    if (characteristics == nullptr) return BAD_VALUE;

    if (!overrideForPerfClass && mCameraCharNoPCOverride != nullptr) {
        *characteristics = *mCameraCharNoPCOverride;
    } else {
        *characteristics = mCameraCharacteristics;
    }

    return OK;
}

status_t CameraProviderManager::ProviderInfo::DeviceInfo3::getPhysicalCameraCharacteristics(
        const std::string& physicalCameraId, CameraMetadata *characteristics) const {
    if (characteristics == nullptr) return BAD_VALUE;
    if (mPhysicalCameraCharacteristics.find(physicalCameraId) ==
            mPhysicalCameraCharacteristics.end()) {
        return NAME_NOT_FOUND;
    }

    *characteristics = mPhysicalCameraCharacteristics.at(physicalCameraId);
    return OK;
}

status_t CameraProviderManager::ProviderInfo::DeviceInfo3::filterSmallJpegSizes() {
    int32_t thresholdW = SessionConfigurationUtils::PERF_CLASS_JPEG_THRESH_W;
    int32_t thresholdH = SessionConfigurationUtils::PERF_CLASS_JPEG_THRESH_H;

    if (mCameraCharNoPCOverride != nullptr) return OK;

    mCameraCharNoPCOverride = std::make_unique<CameraMetadata>(mCameraCharacteristics);

    // Remove small JPEG sizes from available stream configurations
    size_t largeJpegCount = 0;
    std::vector<int32_t> newStreamConfigs;
    camera_metadata_entry streamConfigs =
            mCameraCharacteristics.find(ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS);
    for (size_t i = 0; i < streamConfigs.count; i += 4) {
        if ((streamConfigs.data.i32[i] == HAL_PIXEL_FORMAT_BLOB) && (streamConfigs.data.i32[i+3] ==
                ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS_OUTPUT)) {
            if (streamConfigs.data.i32[i+1] < thresholdW  ||
                    streamConfigs.data.i32[i+2] < thresholdH) {
                continue;
            } else {
                largeJpegCount ++;
            }
        }
        newStreamConfigs.insert(newStreamConfigs.end(), streamConfigs.data.i32 + i,
                streamConfigs.data.i32 + i + 4);
    }
    if (newStreamConfigs.size() == 0 || largeJpegCount == 0) {
        return BAD_VALUE;
    }

    // Remove small JPEG sizes from available min frame durations
    largeJpegCount = 0;
    std::vector<int64_t> newMinDurations;
    camera_metadata_entry minDurations =
            mCameraCharacteristics.find(ANDROID_SCALER_AVAILABLE_MIN_FRAME_DURATIONS);
    for (size_t i = 0; i < minDurations.count; i += 4) {
        if (minDurations.data.i64[i] == HAL_PIXEL_FORMAT_BLOB) {
            if (minDurations.data.i64[i+1] < thresholdW ||
                    minDurations.data.i64[i+2] < thresholdH) {
                continue;
            } else {
                largeJpegCount++;
            }
        }
        newMinDurations.insert(newMinDurations.end(), minDurations.data.i64 + i,
                minDurations.data.i64 + i + 4);
    }
    if (newMinDurations.size() == 0 || largeJpegCount == 0) {
        return BAD_VALUE;
    }

    // Remove small JPEG sizes from available stall durations
    largeJpegCount = 0;
    std::vector<int64_t> newStallDurations;
    camera_metadata_entry stallDurations =
            mCameraCharacteristics.find(ANDROID_SCALER_AVAILABLE_STALL_DURATIONS);
    for (size_t i = 0; i < stallDurations.count; i += 4) {
        if (stallDurations.data.i64[i] == HAL_PIXEL_FORMAT_BLOB) {
            if (stallDurations.data.i64[i+1] < thresholdW ||
                    stallDurations.data.i64[i+2] < thresholdH) {
                continue;
            } else {
                largeJpegCount++;
            }
        }
        newStallDurations.insert(newStallDurations.end(), stallDurations.data.i64 + i,
                stallDurations.data.i64 + i + 4);
    }
    if (newStallDurations.size() == 0 || largeJpegCount == 0) {
        return BAD_VALUE;
    }

    mCameraCharacteristics.update(ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS,
            newStreamConfigs.data(), newStreamConfigs.size());
    mCameraCharacteristics.update(ANDROID_SCALER_AVAILABLE_MIN_FRAME_DURATIONS,
            newMinDurations.data(), newMinDurations.size());
    mCameraCharacteristics.update(ANDROID_SCALER_AVAILABLE_STALL_DURATIONS,
            newStallDurations.data(), newStallDurations.size());

    // Re-generate metadata tags that have dependencies on BLOB sizes
    auto res = addDynamicDepthTags();
    if (OK != res) {
        ALOGE("%s: Failed to append dynamic depth tags: %s (%d)", __FUNCTION__,
                strerror(-res), res);
        // Allow filtering of small JPEG sizes to succeed even if dynamic depth
        // tags fail to generate.
    }

    return OK;
}

status_t CameraProviderManager::ProviderInfo::parseProviderName(const std::string& name,
        std::string *type, uint32_t *id) {
    // Format must be "<type>/<id>"
#define ERROR_MSG_PREFIX "%s: Invalid provider name '%s'. "       \
    "Should match '<type>/<id>' - "

    if (!type || !id) return INVALID_OPERATION;

    std::string::size_type slashIdx = name.find('/');
    if (slashIdx == std::string::npos || slashIdx == name.size() - 1) {
        ALOGE(ERROR_MSG_PREFIX
                "does not have / separator between type and id",
                __FUNCTION__, name.c_str());
        return BAD_VALUE;
    }

    std::string typeVal = name.substr(0, slashIdx);

    char *endPtr;
    errno = 0;
    long idVal = strtol(name.c_str() + slashIdx + 1, &endPtr, 10);
    if (errno != 0) {
        ALOGE(ERROR_MSG_PREFIX
                "cannot parse provider id as an integer: %s (%d)",
                __FUNCTION__, name.c_str(), strerror(errno), errno);
        return BAD_VALUE;
    }
    if (endPtr != name.c_str() + name.size()) {
        ALOGE(ERROR_MSG_PREFIX
                "provider id has unexpected length",
                __FUNCTION__, name.c_str());
        return BAD_VALUE;
    }
    if (idVal < 0) {
        ALOGE(ERROR_MSG_PREFIX
                "id is negative: %ld",
                __FUNCTION__, name.c_str(), idVal);
        return BAD_VALUE;
    }

#undef ERROR_MSG_PREFIX

    *type = typeVal;
    *id = static_cast<uint32_t>(idVal);

    return OK;
}

metadata_vendor_id_t CameraProviderManager::ProviderInfo::generateVendorTagId(
        const std::string &name) {
    metadata_vendor_id_t ret = std::hash<std::string> {} (name);
    // CAMERA_METADATA_INVALID_VENDOR_ID is not a valid hash value
    if (CAMERA_METADATA_INVALID_VENDOR_ID == ret) {
        ret = 0;
    }

    return ret;
}

status_t CameraProviderManager::ProviderInfo::parseDeviceName(const std::string& name,
        uint16_t *major, uint16_t *minor, std::string *type, std::string *id) {

    // Format must be "device@<major>.<minor>/<type>/<id>"

#define ERROR_MSG_PREFIX "%s: Invalid device name '%s'. " \
    "Should match 'device@<major>.<minor>/<type>/<id>' - "

    if (!major || !minor || !type || !id) return INVALID_OPERATION;

    // Verify starting prefix
    const char expectedPrefix[] = "device@";

    if (name.find(expectedPrefix) != 0) {
        ALOGE(ERROR_MSG_PREFIX
                "does not start with '%s'",
                __FUNCTION__, name.c_str(), expectedPrefix);
        return BAD_VALUE;
    }

    // Extract major/minor versions
    constexpr std::string::size_type atIdx = sizeof(expectedPrefix) - 2;
    std::string::size_type dotIdx = name.find('.', atIdx);
    if (dotIdx == std::string::npos) {
        ALOGE(ERROR_MSG_PREFIX
                "does not have @<major>. version section",
                __FUNCTION__, name.c_str());
        return BAD_VALUE;
    }
    std::string::size_type typeSlashIdx = name.find('/', dotIdx);
    if (typeSlashIdx == std::string::npos) {
        ALOGE(ERROR_MSG_PREFIX
                "does not have .<minor>/ version section",
                __FUNCTION__, name.c_str());
        return BAD_VALUE;
    }

    char *endPtr;
    errno = 0;
    long majorVal = strtol(name.c_str() + atIdx + 1, &endPtr, 10);
    if (errno != 0) {
        ALOGE(ERROR_MSG_PREFIX
                "cannot parse major version: %s (%d)",
                __FUNCTION__, name.c_str(), strerror(errno), errno);
        return BAD_VALUE;
    }
    if (endPtr != name.c_str() + dotIdx) {
        ALOGE(ERROR_MSG_PREFIX
                "major version has unexpected length",
                __FUNCTION__, name.c_str());
        return BAD_VALUE;
    }
    long minorVal = strtol(name.c_str() + dotIdx + 1, &endPtr, 10);
    if (errno != 0) {
        ALOGE(ERROR_MSG_PREFIX
                "cannot parse minor version: %s (%d)",
                __FUNCTION__, name.c_str(), strerror(errno), errno);
        return BAD_VALUE;
    }
    if (endPtr != name.c_str() + typeSlashIdx) {
        ALOGE(ERROR_MSG_PREFIX
                "minor version has unexpected length",
                __FUNCTION__, name.c_str());
        return BAD_VALUE;
    }
    if (majorVal < 0 || majorVal > UINT16_MAX || minorVal < 0 || minorVal > UINT16_MAX) {
        ALOGE(ERROR_MSG_PREFIX
                "major/minor version is out of range of uint16_t: %ld.%ld",
                __FUNCTION__, name.c_str(), majorVal, minorVal);
        return BAD_VALUE;
    }

    // Extract type and id

    std::string::size_type instanceSlashIdx = name.find('/', typeSlashIdx + 1);
    if (instanceSlashIdx == std::string::npos) {
        ALOGE(ERROR_MSG_PREFIX
                "does not have /<type>/ component",
                __FUNCTION__, name.c_str());
        return BAD_VALUE;
    }
    std::string typeVal = name.substr(typeSlashIdx + 1, instanceSlashIdx - typeSlashIdx - 1);

    if (instanceSlashIdx == name.size() - 1) {
        ALOGE(ERROR_MSG_PREFIX
                "does not have an /<id> component",
                __FUNCTION__, name.c_str());
        return BAD_VALUE;
    }
    std::string idVal = name.substr(instanceSlashIdx + 1);

#undef ERROR_MSG_PREFIX

    *major = static_cast<uint16_t>(majorVal);
    *minor = static_cast<uint16_t>(minorVal);
    *type = typeVal;
    *id = idVal;

    return OK;
}

CameraProviderManager::ProviderInfo::~ProviderInfo() {
    if (mInitialStatusCallbackFuture.valid()) {
        mInitialStatusCallbackFuture.wait();
    }
    // Destruction of ProviderInfo is only supposed to happen when the respective
    // CameraProvider interface dies, so do not unregister callbacks.
}

// Expects to have mInterfaceMutex locked
std::vector<std::unordered_set<std::string>>
CameraProviderManager::getConcurrentCameraIds() const {
    std::vector<std::unordered_set<std::string>> deviceIdCombinations;
    std::lock_guard<std::mutex> lock(mInterfaceMutex);
    for (auto &provider : mProviders) {
        for (auto &combinations : provider->getConcurrentCameraIdCombinations()) {
            deviceIdCombinations.push_back(combinations);
        }
    }
    return deviceIdCombinations;
}

// Checks if the containing vector of sets has any set that contains all of the
// camera ids in cameraIdsAndSessionConfigs.
static bool checkIfSetContainsAll(
        const std::vector<CameraIdAndSessionConfiguration> &cameraIdsAndSessionConfigs,
        const std::vector<std::unordered_set<std::string>> &containingSets) {
    for (auto &containingSet : containingSets) {
        bool didHaveAll = true;
        for (auto &cameraIdAndSessionConfig : cameraIdsAndSessionConfigs) {
            if (containingSet.find(cameraIdAndSessionConfig.mCameraId) == containingSet.end()) {
                // a camera id doesn't belong to this set, keep looking in other
                // sets
                didHaveAll = false;
                break;
            }
        }
        if (didHaveAll) {
            // found a set that has all camera ids, lets return;
            return true;
        }
    }
    return false;
}

status_t CameraProviderManager::isConcurrentSessionConfigurationSupported(
        const std::vector<CameraIdAndSessionConfiguration> &cameraIdsAndSessionConfigs,
        const std::set<std::string>& perfClassPrimaryCameraIds,
        int targetSdkVersion, bool *isSupported) {
    std::lock_guard<std::mutex> lock(mInterfaceMutex);
    // Check if all the devices are a subset of devices advertised by the
    // same provider through getConcurrentStreamingCameraIds()
    // TODO: we should also do a findDeviceInfoLocked here ?
    for (auto &provider : mProviders) {
        if (checkIfSetContainsAll(cameraIdsAndSessionConfigs,
                provider->getConcurrentCameraIdCombinations())) {
            return provider->isConcurrentSessionConfigurationSupported(
                    cameraIdsAndSessionConfigs, perfClassPrimaryCameraIds, targetSdkVersion,
                    isSupported);
        }
    }
    *isSupported = false;
    //The set of camera devices were not found
    return INVALID_OPERATION;
}

status_t CameraProviderManager::getCameraCharacteristicsLocked(const std::string &id,
        bool overrideForPerfClass, CameraMetadata* characteristics) const {
    auto deviceInfo = findDeviceInfoLocked(id);
    if (deviceInfo != nullptr) {
        return deviceInfo->getCameraCharacteristics(overrideForPerfClass, characteristics);
    }

    // Find hidden physical camera characteristics
    for (auto& provider : mProviders) {
        for (auto& deviceInfo : provider->mDevices) {
            status_t res = deviceInfo->getPhysicalCameraCharacteristics(id, characteristics);
            if (res != NAME_NOT_FOUND) return res;
        }
    }

    return NAME_NOT_FOUND;
}

void CameraProviderManager::filterLogicalCameraIdsLocked(
        std::vector<std::string>& deviceIds) const
{
    // Map between camera facing and camera IDs related to logical camera.
    std::map<int, std::unordered_set<std::string>> idCombos;

    // Collect all logical and its underlying physical camera IDs for each
    // facing.
    for (auto& deviceId : deviceIds) {
        auto deviceInfo = findDeviceInfoLocked(deviceId);
        if (deviceInfo == nullptr) continue;

        if (!deviceInfo->mIsLogicalCamera) {
            continue;
        }

        // combo contains the ids of a logical camera and its physical cameras
        std::vector<std::string> combo = deviceInfo->mPhysicalIds;
        combo.push_back(deviceId);

        hardware::CameraInfo info;
        status_t res = deviceInfo->getCameraInfo(&info);
        if (res != OK) {
            ALOGE("%s: Error reading camera info: %s (%d)", __FUNCTION__, strerror(-res), res);
            continue;
        }
        idCombos[info.facing].insert(combo.begin(), combo.end());
    }

    // Only expose one camera ID per facing for all logical and underlying
    // physical camera IDs.
    for (auto& r : idCombos) {
        auto& removedIds = r.second;
        for (auto& id : deviceIds) {
            auto foundId = std::find(removedIds.begin(), removedIds.end(), id);
            if (foundId == removedIds.end()) {
                continue;
            }

            removedIds.erase(foundId);
            break;
        }
        deviceIds.erase(std::remove_if(deviceIds.begin(), deviceIds.end(),
                [&removedIds](const std::string& s) {
                return removedIds.find(s) != removedIds.end();}),
                deviceIds.end());
    }
}

} // namespace android
