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

#include <chrono>
#include <hidl/ServiceManagement.h>

namespace android {

using namespace ::android::hardware::camera;
using namespace ::android::hardware::camera::common::V1_0;

namespace {
// Hardcoded name for the passthrough HAL implementation, since it can't be discovered via the
// service manager
const std::string kLegacyProviderName("legacy/0");

// Slash-separated list of provider types to consider for use via the old camera API
const std::string kStandardProviderTypes("internal/legacy");

} // anonymous namespace

CameraProviderManager::HardwareServiceInteractionProxy
CameraProviderManager::sHardwareServiceInteractionProxy{};

CameraProviderManager::~CameraProviderManager() {
}

status_t CameraProviderManager::initialize(wp<CameraProviderManager::StatusListener> listener,
        ServiceInteractionProxy* proxy) {
    std::lock_guard<std::mutex> lock(mInterfaceMutex);
    if (proxy == nullptr) {
        ALOGE("%s: No valid service interaction proxy provided", __FUNCTION__);
        return BAD_VALUE;
    }
    mListener = listener;
    mServiceProxy = proxy;

    // Registering will trigger notifications for all already-known providers
    bool success = mServiceProxy->registerForNotifications(
        /* instance name, empty means no filter */ "",
        this);
    if (!success) {
        ALOGE("%s: Unable to register with hardware service manager for notifications "
                "about camera providers", __FUNCTION__);
        return INVALID_OPERATION;
    }
    // See if there's a passthrough HAL, but let's not complain if there's not
    addProvider(kLegacyProviderName, /*expected*/ false);
    return OK;
}

int CameraProviderManager::getCameraCount() const {
    std::lock_guard<std::mutex> lock(mInterfaceMutex);
    int count = 0;
    for (auto& provider : mProviders) {
        count += provider->mDevices.size();
    }
    return count;
}

int CameraProviderManager::getStandardCameraCount() const {
    std::lock_guard<std::mutex> lock(mInterfaceMutex);
    int count = 0;
    for (auto& provider : mProviders) {
        if (kStandardProviderTypes.find(provider->getType()) != std::string::npos) {
            count += provider->mDevices.size();
        }
    }
    return count;
}

std::vector<std::string> CameraProviderManager::getCameraDeviceIds() const {
    std::lock_guard<std::mutex> lock(mInterfaceMutex);
    std::vector<std::string> deviceIds;
    for (auto& provider : mProviders) {
        for (auto& deviceInfo : provider->mDevices) {
            deviceIds.push_back(deviceInfo->mId);
        }
    }
    return deviceIds;
}

bool CameraProviderManager::isValidDevice(const std::string &id, uint16_t majorVersion) const {
    std::lock_guard<std::mutex> lock(mInterfaceMutex);
    return isValidDeviceLocked(id, majorVersion);
}

bool CameraProviderManager::isValidDeviceLocked(const std::string &id, uint16_t majorVersion) const {
    for (auto& provider : mProviders) {
        for (auto& deviceInfo : provider->mDevices) {
            if (deviceInfo->mId == id && deviceInfo->mVersion.get_major() == majorVersion) {
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

status_t CameraProviderManager::getCameraCharacteristics(const std::string &id,
        CameraMetadata* characteristics) const {
    std::lock_guard<std::mutex> lock(mInterfaceMutex);

    auto deviceInfo = findDeviceInfoLocked(id, /*minVersion*/ {3,0}, /*maxVersion*/ {4,0});
    if (deviceInfo == nullptr) return NAME_NOT_FOUND;

    return deviceInfo->getCameraCharacteristics(characteristics);
}

status_t CameraProviderManager::getHighestSupportedVersion(const std::string &id,
        hardware::hidl_version *v) {
    std::lock_guard<std::mutex> lock(mInterfaceMutex);

    hardware::hidl_version maxVersion{0,0};
    bool found = false;
    for (auto& provider : mProviders) {
        for (auto& deviceInfo : provider->mDevices) {
            if (deviceInfo->mId == id) {
                if (deviceInfo->mVersion > maxVersion) {
                    maxVersion = deviceInfo->mVersion;
                    found = true;
                }
            }
        }
    }
    if (!found) {
        return NAME_NOT_FOUND;
    }
    *v = maxVersion;
    return OK;
}

status_t CameraProviderManager::setTorchMode(const std::string &id, bool enabled) {
    std::lock_guard<std::mutex> lock(mInterfaceMutex);

    auto deviceInfo = findDeviceInfoLocked(id);
    if (deviceInfo == nullptr) return NAME_NOT_FOUND;

    return deviceInfo->setTorchMode(enabled);
}

status_t CameraProviderManager::setUpVendorTags() {
    // TODO (b/34275821): support aggregating vendor tags for more than one provider
    for (auto& provider : mProviders) {
        hardware::hidl_vec<VendorTagSection> vts;
        Status status;
        provider->mInterface->getVendorTags(
            [&](auto s, const auto& vendorTagSecs) {
                status = s;
                if (s == Status::OK) {
                    vts = vendorTagSecs;
                }
        });

        if (status != Status::OK) {
            return mapToStatusT(status);
        }

        VendorTagDescriptor::clearGlobalVendorTagDescriptor();

        // Read all vendor tag definitions into a descriptor
        sp<VendorTagDescriptor> desc;
        status_t res;
        if ((res = HidlVendorTagDescriptor::createDescriptorFromHidl(vts, /*out*/desc))
                != OK) {
            ALOGE("%s: Could not generate descriptor from vendor tag operations,"
                  "received error %s (%d). Camera clients will not be able to use"
                  "vendor tags", __FUNCTION__, strerror(res), res);
            return res;
        }

        // Set the global descriptor to use with camera metadata
        VendorTagDescriptor::setAsGlobalVendorTagDescriptor(desc);
    }
    return OK;
}

status_t CameraProviderManager::openSession(const std::string &id,
        const sp<hardware::camera::device::V3_2::ICameraDeviceCallback>& callback,
        /*out*/
        sp<hardware::camera::device::V3_2::ICameraDeviceSession> *session) {

    std::lock_guard<std::mutex> lock(mInterfaceMutex);

    auto deviceInfo = findDeviceInfoLocked(id,
            /*minVersion*/ {3,0}, /*maxVersion*/ {4,0});
    if (deviceInfo == nullptr) return NAME_NOT_FOUND;

    auto *deviceInfo3 = static_cast<ProviderInfo::DeviceInfo3*>(deviceInfo);

    Status status;
    deviceInfo3->mInterface->open(callback, [&status, &session]
            (Status s, const sp<device::V3_2::ICameraDeviceSession>& cameraSession) {
                status = s;
                if (status == Status::OK) {
                    *session = cameraSession;
                }
            });
    return mapToStatusT(status);
}

status_t CameraProviderManager::openSession(const std::string &id,
        const sp<hardware::camera::device::V1_0::ICameraDeviceCallback>& callback,
        /*out*/
        sp<hardware::camera::device::V1_0::ICameraDevice> *session) {

    std::lock_guard<std::mutex> lock(mInterfaceMutex);

    auto deviceInfo = findDeviceInfoLocked(id,
            /*minVersion*/ {1,0}, /*maxVersion*/ {2,0});
    if (deviceInfo == nullptr) return NAME_NOT_FOUND;

    auto *deviceInfo1 = static_cast<ProviderInfo::DeviceInfo1*>(deviceInfo);

    Status status = deviceInfo1->mInterface->open(callback);
    if (status == Status::OK) {
        *session = deviceInfo1->mInterface;
    }
    return mapToStatusT(status);
}


hardware::Return<void> CameraProviderManager::onRegistration(
        const hardware::hidl_string& /*fqName*/,
        const hardware::hidl_string& name,
        bool /*preexisting*/) {
    std::lock_guard<std::mutex> lock(mInterfaceMutex);

    addProvider(name);
    return hardware::Return<void>();
}

status_t CameraProviderManager::dump(int fd, const Vector<String16>& args) {
    std::lock_guard<std::mutex> lock(mInterfaceMutex);

    for (auto& provider : mProviders) {
        provider->dump(fd, args);
    }
    return OK;
}

CameraProviderManager::ProviderInfo::DeviceInfo* CameraProviderManager::findDeviceInfoLocked(
        const std::string& id,
        hardware::hidl_version minVersion, hardware::hidl_version maxVersion) const {
    for (auto& provider : mProviders) {
        for (auto& deviceInfo : provider->mDevices) {
            if (deviceInfo->mId == id &&
                    minVersion <= deviceInfo->mVersion && maxVersion >= deviceInfo->mVersion) {
                return deviceInfo.get();
            }
        }
    }
    return nullptr;
}


status_t CameraProviderManager::addProvider(const std::string& newProvider, bool expected) {
    for (const auto& providerInfo : mProviders) {
        if (providerInfo->mProviderName == newProvider) {
            ALOGW("%s: Camera provider HAL with name '%s' already registered", __FUNCTION__,
                    newProvider.c_str());
            return ALREADY_EXISTS;
        }
    }
    sp<provider::V2_4::ICameraProvider> interface =
            mServiceProxy->getService(newProvider);

    if (interface == nullptr) {
        ALOGW("%s: Camera provider HAL '%s' is not actually available", __FUNCTION__,
                newProvider.c_str());
        if (expected) {
            return BAD_VALUE;
        } else {
            return OK;
        }
    }

    sp<ProviderInfo> providerInfo =
            new ProviderInfo(newProvider, interface, this);
    status_t res = providerInfo->initialize();
    if (res != OK) {
        return res;
    }

    mProviders.push_back(providerInfo);

    return OK;
}

status_t CameraProviderManager::removeProvider(const std::string& provider) {
    for (auto it = mProviders.begin(); it != mProviders.end(); it++) {
        if ((*it)->mProviderName == provider) {
            mProviders.erase(it);
            return OK;
        }
    }
    ALOGW("%s: Camera provider HAL with name '%s' is not registered", __FUNCTION__,
            provider.c_str());
    return NAME_NOT_FOUND;
}

/**** Methods for ProviderInfo ****/


CameraProviderManager::ProviderInfo::ProviderInfo(
        const std::string &providerName,
        sp<provider::V2_4::ICameraProvider>& interface,
        CameraProviderManager *manager) :
        mProviderName(providerName),
        mInterface(interface),
        mManager(manager) {
    (void) mManager;
}

status_t CameraProviderManager::ProviderInfo::initialize() {
    status_t res = parseProviderName(mProviderName, &mType, &mId);
    if (res != OK) {
        ALOGE("%s: Invalid provider name, ignoring", __FUNCTION__);
        return BAD_VALUE;
    }
    ALOGI("Connecting to new camera provider: %s, isRemote? %d",
            mProviderName.c_str(), mInterface->isRemote());
    Status status = mInterface->setCallback(this);
    if (status != Status::OK) {
        ALOGE("%s: Unable to register callbacks with camera provider '%s'",
                __FUNCTION__, mProviderName.c_str());
        return mapToStatusT(status);
    }
    // TODO: Register for hw binder death notifications as well

    // Get initial list of camera devices, if any
    std::vector<std::string> devices;
    mInterface->getCameraIdList([&status, &devices](
            Status idStatus,
            const hardware::hidl_vec<hardware::hidl_string>& cameraDeviceNames) {
        status = idStatus;
        if (status == Status::OK) {
            for (size_t i = 0; i < cameraDeviceNames.size(); i++) {
                devices.push_back(cameraDeviceNames[i]);
            }
        } });

    if (status != Status::OK) {
        ALOGE("%s: Unable to query for camera devices from provider '%s'",
                __FUNCTION__, mProviderName.c_str());
        return mapToStatusT(status);
    }

    for (auto& device : devices) {
        status_t res = addDevice(device);
        if (res != OK) {
            ALOGE("%s: Unable to enumerate camera device '%s': %s (%d)",
                    __FUNCTION__, device.c_str(), strerror(-res), res);
        }
    }

    ALOGI("Camera provider %s ready with %zu camera devices",
            mProviderName.c_str(), mDevices.size());

    return OK;
}

const std::string& CameraProviderManager::ProviderInfo::getType() const {
    return mType;
}

status_t CameraProviderManager::ProviderInfo::addDevice(const std::string& name,
        CameraDeviceStatus initialStatus, /*out*/ std::string* parsedId) {

    ALOGI("Enumerating new camera device: %s", name.c_str());

    uint16_t major, minor;
    std::string type, id;

    status_t res = parseDeviceName(name, &major, &minor, &type, &id);
    if (res != OK) {
        return res;
    }
    if (type != mType) {
        ALOGE("%s: Device type %s does not match provider type %s", __FUNCTION__,
                type.c_str(), mType.c_str());
        return BAD_VALUE;
    }
    if (mManager->isValidDeviceLocked(id, major)) {
        ALOGE("%s: Device %s: ID %s is already in use for device major version %d", __FUNCTION__,
                name.c_str(), id.c_str(), major);
        return BAD_VALUE;
    }

    std::unique_ptr<DeviceInfo> deviceInfo;
    switch (major) {
        case 1:
            deviceInfo = initializeDeviceInfo<DeviceInfo1>(name, id, minor);
            break;
        case 3:
            deviceInfo = initializeDeviceInfo<DeviceInfo3>(name, id, minor);
            break;
        default:
            ALOGE("%s: Device %s: Unknown HIDL device HAL major version %d:", __FUNCTION__,
                    name.c_str(), major);
            return BAD_VALUE;
    }
    if (deviceInfo == nullptr) return BAD_VALUE;
    deviceInfo->mStatus = initialStatus;

    mDevices.push_back(std::move(deviceInfo));

    if (parsedId != nullptr) {
        *parsedId = id;
    }
    return OK;
}

status_t CameraProviderManager::ProviderInfo::dump(int fd, const Vector<String16>&) const {
    dprintf(fd, "== Camera Provider HAL %s (v2.4) static info: %zu devices: ==\n",
            mProviderName.c_str(), mDevices.size());

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
        res = device->getCameraCharacteristics(&info2);
        if (res == INVALID_OPERATION) {
            dprintf(fd, "  API2 not directly supported\n");
        } else if (res != OK) {
            dprintf(fd, "  <Error reading camera characteristics: %s (%d)>\n",
                    strerror(-res), res);
        } else {
            dprintf(fd, "  API2 camera characteristics:\n");
            info2.dump(fd, /*verbosity*/ 2, /*indentation*/ 4);
        }
    }
    return OK;
}

hardware::Return<void> CameraProviderManager::ProviderInfo::cameraDeviceStatusChange(
        const hardware::hidl_string& cameraDeviceName,
        CameraDeviceStatus newStatus) {
    sp<StatusListener> listener;
    std::string id;
    {
        std::lock_guard<std::mutex> lock(mManager->mStatusListenerMutex);
        bool known = false;
        for (auto& deviceInfo : mDevices) {
            if (deviceInfo->mName == cameraDeviceName) {
                ALOGI("Camera device %s status is now %s, was %s", cameraDeviceName.c_str(),
                        deviceStatusToString(newStatus), deviceStatusToString(deviceInfo->mStatus));
                deviceInfo->mStatus = newStatus;
                // TODO: Handle device removal (NOT_PRESENT)
                id = deviceInfo->mId;
                known = true;
                break;
            }
        }
        // Previously unseen device; status must not be NOT_PRESENT
        if (!known) {
            if (newStatus == CameraDeviceStatus::NOT_PRESENT) {
                ALOGW("Camera provider %s says an unknown camera device %s is not present. Curious.",
                    mProviderName.c_str(), cameraDeviceName.c_str());
                return hardware::Void();
            }
            addDevice(cameraDeviceName, newStatus, &id);
        }
        listener = mManager->mListener.promote();
    }
    // Call without lock held to allow reentrancy into provider manager
    if (listener != nullptr) {
        listener->onDeviceStatusChanged(String8(id.c_str()), newStatus);
    }
    return hardware::Void();
}

hardware::Return<void> CameraProviderManager::ProviderInfo::torchModeStatusChange(
        const hardware::hidl_string& cameraDeviceName,
        TorchModeStatus newStatus) {
    sp<StatusListener> listener;
    std::string id;
    {
        std::lock_guard<std::mutex> lock(mManager->mStatusListenerMutex);
        bool known = false;
        for (auto& deviceInfo : mDevices) {
            if (deviceInfo->mName == cameraDeviceName) {
                ALOGI("Camera device %s torch status is now %s", cameraDeviceName.c_str(),
                        torchStatusToString(newStatus));
                id = deviceInfo->mId;
                known = true;
                break;
            }
        }
        if (!known) {
            ALOGW("Camera provider %s says an unknown camera %s now has torch status %d. Curious.",
                    mProviderName.c_str(), cameraDeviceName.c_str(), newStatus);
            return hardware::Void();
        }
        listener = mManager->mListener.promote();
    }
    // Call without lock held to allow reentrancy into provider manager
    if (listener != nullptr) {
        listener->onTorchStatusChanged(String8(id.c_str()), newStatus);
    }
    return hardware::Void();
}


template<class DeviceInfoT>
std::unique_ptr<CameraProviderManager::ProviderInfo::DeviceInfo>
    CameraProviderManager::ProviderInfo::initializeDeviceInfo(
        const std::string &name,
        const std::string &id, uint16_t minorVersion) const {
    Status status;

    auto cameraInterface =
            getDeviceInterface<typename DeviceInfoT::InterfaceT>(name);
    if (cameraInterface == nullptr) return nullptr;

    CameraResourceCost resourceCost;
    cameraInterface->getResourceCost([&status, &resourceCost](
        Status s, CameraResourceCost cost) {
                status = s;
                resourceCost = cost;
            });
    if (status != Status::OK) {
        ALOGE("%s: Unable to obtain resource costs for camera device %s: %s", __FUNCTION__,
                name.c_str(), statusToString(status));
        return nullptr;
    }
    return std::unique_ptr<DeviceInfo>(
        new DeviceInfoT(name, id, minorVersion, resourceCost, cameraInterface));
}

template<class InterfaceT>
sp<InterfaceT>
CameraProviderManager::ProviderInfo::getDeviceInterface(const std::string &name) const {
    ALOGE("%s: Device %s: Unknown HIDL device HAL major version %d:", __FUNCTION__,
            name.c_str(), InterfaceT::version.get_major());
    return nullptr;
}

template<>
sp<device::V1_0::ICameraDevice>
CameraProviderManager::ProviderInfo::getDeviceInterface
        <device::V1_0::ICameraDevice>(const std::string &name) const {
    Status status;
    sp<device::V1_0::ICameraDevice> cameraInterface;
    mInterface->getCameraDeviceInterface_V1_x(name, [&status, &cameraInterface](
        Status s, sp<device::V1_0::ICameraDevice> interface) {
                status = s;
                cameraInterface = interface;
            });
    if (status != Status::OK) {
        ALOGE("%s: Unable to obtain interface for camera device %s: %s", __FUNCTION__,
                name.c_str(), statusToString(status));
        return nullptr;
    }
    return cameraInterface;
}

template<>
sp<device::V3_2::ICameraDevice>
CameraProviderManager::ProviderInfo::getDeviceInterface
        <device::V3_2::ICameraDevice>(const std::string &name) const {
    Status status;
    sp<device::V3_2::ICameraDevice> cameraInterface;
    mInterface->getCameraDeviceInterface_V3_x(name, [&status, &cameraInterface](
        Status s, sp<device::V3_2::ICameraDevice> interface) {
                status = s;
                cameraInterface = interface;
            });
    if (status != Status::OK) {
        ALOGE("%s: Unable to obtain interface for camera device %s: %s", __FUNCTION__,
                name.c_str(), statusToString(status));
        return nullptr;
    }
    return cameraInterface;
}

CameraProviderManager::ProviderInfo::DeviceInfo::~DeviceInfo() {}

template<class InterfaceT>
status_t CameraProviderManager::ProviderInfo::DeviceInfo::setTorchMode(InterfaceT& interface,
        bool enabled) {
    Status s = interface->setTorchMode(enabled ? TorchMode::ON : TorchMode::OFF);
    return mapToStatusT(s);
}

CameraProviderManager::ProviderInfo::DeviceInfo1::DeviceInfo1(const std::string& name,
        const std::string &id,
        uint16_t minorVersion,
        const CameraResourceCost& resourceCost,
        sp<InterfaceT> interface) :
        DeviceInfo(name, id, hardware::hidl_version{1, minorVersion}, resourceCost),
        mInterface(interface) {
    // Get default parameters and initialize flash unit availability
    // Requires powering on the camera device
    Status status = mInterface->open(nullptr);
    if (status != Status::OK) {
        ALOGE("%s: Unable to open camera device %s to check for a flash unit: %s (%d)", __FUNCTION__,
                mId.c_str(), CameraProviderManager::statusToString(status), status);
        return;
    }
    mInterface->getParameters([this](const hardware::hidl_string& parms) {
                mDefaultParameters.unflatten(String8(parms.c_str()));
            });

    const char *flashMode =
            mDefaultParameters.get(CameraParameters::KEY_SUPPORTED_FLASH_MODES);
    if (flashMode && strstr(flashMode, CameraParameters::FLASH_MODE_TORCH)) {
        mHasFlashUnit = true;
    } else {
        mHasFlashUnit = false;
    }

    mInterface->close();
}

CameraProviderManager::ProviderInfo::DeviceInfo1::~DeviceInfo1() {}

status_t CameraProviderManager::ProviderInfo::DeviceInfo1::setTorchMode(bool enabled) {
    return DeviceInfo::setTorchMode(mInterface, enabled);
}

status_t CameraProviderManager::ProviderInfo::DeviceInfo1::getCameraInfo(
        hardware::CameraInfo *info) const {
    if (info == nullptr) return BAD_VALUE;

    Status status;
    device::V1_0::CameraInfo cInfo;
    mInterface->getCameraInfo([&status, &cInfo](Status s, device::V1_0::CameraInfo camInfo) {
                status = s;
                cInfo = camInfo;
            });
    if (status != Status::OK) {
        return mapToStatusT(status);
    }

    switch(cInfo.facing) {
        case device::V1_0::CameraFacing::BACK:
            info->facing = hardware::CAMERA_FACING_BACK;
            break;
        case device::V1_0::CameraFacing::EXTERNAL:
            // Map external to front for legacy API
        case device::V1_0::CameraFacing::FRONT:
            info->facing = hardware::CAMERA_FACING_FRONT;
            break;
        default:
            ALOGW("%s: Unknown camera facing: %d", __FUNCTION__, cInfo.facing);
            info->facing = hardware::CAMERA_FACING_BACK;
    }
    info->orientation = cInfo.orientation;

    return OK;
}

CameraProviderManager::ProviderInfo::DeviceInfo3::DeviceInfo3(const std::string& name,
        const std::string &id,
        uint16_t minorVersion,
        const CameraResourceCost& resourceCost,
        sp<InterfaceT> interface) :
        DeviceInfo(name, id, hardware::hidl_version{3, minorVersion}, resourceCost),
        mInterface(interface) {
    // Get camera characteristics and initialize flash unit availability
    Status status;
    mInterface->getCameraCharacteristics([&status, this](Status s,
                    device::V3_2::CameraMetadata metadata) {
                status = s;
                if (s == Status::OK) {
                    camera_metadata_t *buffer =
                            reinterpret_cast<camera_metadata_t*>(metadata.data());
                    mCameraCharacteristics = buffer;
                }
            });
    if (status != Status::OK) {
        ALOGE("%s: Unable to get camera characteristics for device %s: %s (%d)",
                __FUNCTION__, mId.c_str(), CameraProviderManager::statusToString(status), status);
        return;
    }
    camera_metadata_entry flashAvailable =
            mCameraCharacteristics.find(ANDROID_FLASH_INFO_AVAILABLE);
    if (flashAvailable.count == 1 &&
            flashAvailable.data.u8[0] == ANDROID_FLASH_INFO_AVAILABLE_TRUE) {
        mHasFlashUnit = true;
    } else {
        mHasFlashUnit = false;
    }
}

CameraProviderManager::ProviderInfo::DeviceInfo3::~DeviceInfo3() {}

status_t CameraProviderManager::ProviderInfo::DeviceInfo3::setTorchMode(bool enabled) {
    return DeviceInfo::setTorchMode(mInterface, enabled);
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

status_t CameraProviderManager::ProviderInfo::DeviceInfo3::getCameraCharacteristics(
        CameraMetadata *characteristics) const {
    if (characteristics == nullptr) return BAD_VALUE;

    *characteristics = mCameraCharacteristics;
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
    // Destruction of ProviderInfo is only supposed to happen when the respective
    // CameraProvider interface dies, so do not unregister callbacks.

}

status_t CameraProviderManager::mapToStatusT(const Status& s)  {
    switch(s) {
        case Status::OK:
            return OK;
        case Status::ILLEGAL_ARGUMENT:
            return BAD_VALUE;
        case Status::CAMERA_IN_USE:
            return -EBUSY;
        case Status::MAX_CAMERAS_IN_USE:
            return -EUSERS;
        case Status::METHOD_NOT_SUPPORTED:
            return UNKNOWN_TRANSACTION;
        case Status::OPERATION_NOT_SUPPORTED:
            return INVALID_OPERATION;
        case Status::CAMERA_DISCONNECTED:
            return DEAD_OBJECT;
        case Status::INTERNAL_ERROR:
            return INVALID_OPERATION;
    }
    ALOGW("Unexpected HAL status code %d", s);
    return INVALID_OPERATION;
}

const char* CameraProviderManager::statusToString(const Status& s) {
    switch(s) {
        case Status::OK:
            return "OK";
        case Status::ILLEGAL_ARGUMENT:
            return "ILLEGAL_ARGUMENT";
        case Status::CAMERA_IN_USE:
            return "CAMERA_IN_USE";
        case Status::MAX_CAMERAS_IN_USE:
            return "MAX_CAMERAS_IN_USE";
        case Status::METHOD_NOT_SUPPORTED:
            return "METHOD_NOT_SUPPORTED";
        case Status::OPERATION_NOT_SUPPORTED:
            return "OPERATION_NOT_SUPPORTED";
        case Status::CAMERA_DISCONNECTED:
            return "CAMERA_DISCONNECTED";
        case Status::INTERNAL_ERROR:
            return "INTERNAL_ERROR";
    }
    ALOGW("Unexpected HAL status code %d", s);
    return "UNKNOWN_ERROR";
}

const char* CameraProviderManager::deviceStatusToString(const CameraDeviceStatus& s) {
    switch(s) {
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

const char* CameraProviderManager::torchStatusToString(const TorchModeStatus& s) {
    switch(s) {
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


status_t HidlVendorTagDescriptor::createDescriptorFromHidl(
        const hardware::hidl_vec<hardware::camera::common::V1_0::VendorTagSection>& vts,
        /*out*/
        sp<VendorTagDescriptor>& descriptor) {

    int tagCount = 0;

    for (size_t s = 0; s < vts.size(); s++) {
        tagCount += vts[s].tags.size();
    }

    if (tagCount < 0 || tagCount > INT32_MAX) {
        ALOGE("%s: tag count %d from vendor tag sections is invalid.", __FUNCTION__, tagCount);
        return BAD_VALUE;
    }

    Vector<uint32_t> tagArray;
    LOG_ALWAYS_FATAL_IF(tagArray.resize(tagCount) != tagCount,
            "%s: too many (%u) vendor tags defined.", __FUNCTION__, tagCount);


    sp<HidlVendorTagDescriptor> desc = new HidlVendorTagDescriptor();
    desc->mTagCount = tagCount;

    SortedVector<String8> sections;
    KeyedVector<uint32_t, String8> tagToSectionMap;

    int idx = 0;
    for (size_t s = 0; s < vts.size(); s++) {
        const hardware::camera::common::V1_0::VendorTagSection& section = vts[s];
        const char *sectionName = section.sectionName.c_str();
        if (sectionName == NULL) {
            ALOGE("%s: no section name defined for vendor tag section %zu.", __FUNCTION__, s);
            return BAD_VALUE;
        }
        String8 sectionString(sectionName);
        sections.add(sectionString);

        for (size_t j = 0; j < section.tags.size(); j++) {
            uint32_t tag = section.tags[j].tagId;
            if (tag < CAMERA_METADATA_VENDOR_TAG_BOUNDARY) {
                ALOGE("%s: vendor tag %d not in vendor tag section.", __FUNCTION__, tag);
                return BAD_VALUE;
            }

            tagArray.editItemAt(idx++) = section.tags[j].tagId;

            const char *tagName = section.tags[j].tagName.c_str();
            if (tagName == NULL) {
                ALOGE("%s: no tag name defined for vendor tag %d.", __FUNCTION__, tag);
                return BAD_VALUE;
            }
            desc->mTagToNameMap.add(tag, String8(tagName));
            tagToSectionMap.add(tag, sectionString);

            int tagType = (int) section.tags[j].tagType;
            if (tagType < 0 || tagType >= NUM_TYPES) {
                ALOGE("%s: tag type %d from vendor ops does not exist.", __FUNCTION__, tagType);
                return BAD_VALUE;
            }
            desc->mTagToTypeMap.add(tag, tagType);
        }
    }

    desc->mSections = sections;

    for (size_t i = 0; i < tagArray.size(); ++i) {
        uint32_t tag = tagArray[i];
        String8 sectionString = tagToSectionMap.valueFor(tag);

        // Set up tag to section index map
        ssize_t index = sections.indexOf(sectionString);
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

    descriptor = desc;
    return OK;
}


} // namespace android
