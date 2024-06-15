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

#include <map>
#include <memory>
#define LOG_TAG "FactoryHal"

#include <algorithm>
#include <array>
#include <cstddef>
#include <dlfcn.h>
#include <utility>

#include <android/binder_manager.h>
#include <android/hidl/manager/1.0/IServiceManager.h>
#include <hidl/ServiceManagement.h>
#include <hidl/Status.h>
#include <utils/Log.h>

#include "include/media/audiohal/AudioHalVersionInfo.h"
#include "include/media/audiohal/FactoryHal.h"

namespace android::detail {

namespace {

using ::android::detail::AudioHalVersionInfo;

// The pair of the interface's package name and the interface name,
// e.g. <"android.hardware.audio", "IDevicesFactory"> for HIDL, <"android.hardware.audio.core",
// "IModule"> for AIDL.
// Splitting is used for easier construction of versioned names (FQNs).
using InterfaceName = std::pair<std::string, std::string>;

/**
 * Supported HAL versions, from most recent to least recent.
 * This list need to keep sync with AudioHalVersionInfo.VERSIONS in
 * media/java/android/media/AudioHalVersionInfo.java.
 */
static const std::array<AudioHalVersionInfo, 5> sAudioHALVersions = {
    AudioHalVersionInfo(AudioHalVersionInfo::Type::AIDL, 1, 0),
    AudioHalVersionInfo(AudioHalVersionInfo::Type::HIDL, 7, 1),
    AudioHalVersionInfo(AudioHalVersionInfo::Type::HIDL, 7, 0),
    AudioHalVersionInfo(AudioHalVersionInfo::Type::HIDL, 6, 0),
    AudioHalVersionInfo(AudioHalVersionInfo::Type::HIDL, 5, 0),
};

static const std::map<AudioHalVersionInfo::Type, InterfaceName> sDevicesHALInterfaces = {
        {AudioHalVersionInfo::Type::AIDL, std::make_pair("android.hardware.audio.core", "IModule")},
        {AudioHalVersionInfo::Type::HIDL,
         std::make_pair("android.hardware.audio", "IDevicesFactory")},
};

static const std::map<AudioHalVersionInfo::Type, InterfaceName> sEffectsHALInterfaces = {
        {AudioHalVersionInfo::Type::AIDL,
         std::make_pair("android.hardware.audio.effect", "IFactory")},
        {AudioHalVersionInfo::Type::HIDL,
         std::make_pair("android.hardware.audio.effect", "IEffectsFactory")},
};

bool createHalService(const AudioHalVersionInfo& version, bool isDevice, void** rawInterface) {
    const std::string libName = "libaudiohal@" + version.toVersionString() + ".so";
    const std::string factoryFunctionName =
            isDevice ? "createIDevicesFactory" : "createIEffectsFactory";
    constexpr int dlMode = RTLD_LAZY;
    void* handle = nullptr;
    dlerror(); // clear
    handle = dlopen(libName.c_str(), dlMode);
    if (handle == nullptr) {
        const char* error = dlerror();
        ALOGE("Failed to dlopen %s: %s", libName.c_str(),
                error != nullptr ? error : "unknown error");
        return false;
    }
    void* (*factoryFunction)();
    *(void **)(&factoryFunction) = dlsym(handle, factoryFunctionName.c_str());
    if (!factoryFunction) {
        const char* error = dlerror();
        ALOGE("Factory function %s not found in library %s: %s",
                factoryFunctionName.c_str(), libName.c_str(),
                error != nullptr ? error : "unknown error");
        dlclose(handle);
        return false;
    }
    *rawInterface = (*factoryFunction)();
    ALOGW_IF(!*rawInterface, "Factory function %s from %s returned nullptr",
            factoryFunctionName.c_str(), libName.c_str());
    return true;
}

bool hasAidlHalService(const InterfaceName& interface, const AudioHalVersionInfo& version) {
    const std::string name = interface.first + "." + interface.second + "/default";
    const bool isDeclared = AServiceManager_isDeclared(name.c_str());
    if (!isDeclared) {
        ALOGW("%s %s: false", __func__, name.c_str());
        return false;
    }
    ALOGI("%s %s: true, version %s", __func__, name.c_str(), version.toString().c_str());
    return true;
}

bool hasHidlHalService(const InterfaceName& interface, const AudioHalVersionInfo& version) {
    using ::android::hidl::manager::V1_0::IServiceManager;
    sp<IServiceManager> sm = ::android::hardware::defaultServiceManager();
    if (!sm) {
        ALOGW("Failed to obtain HIDL ServiceManager");
        return false;
    }
    // Since audio HAL doesn't support multiple clients, avoid instantiating
    // the interface right away. Instead, query the transport type for it.
    using ::android::hardware::Return;
    using Transport = IServiceManager::Transport;
    const std::string fqName =
            interface.first + "@" + version.toVersionString() + "::" + interface.second;
    const std::string instance = "default";
    Return<Transport> transport = sm->getTransport(fqName, instance);
    if (!transport.isOk()) {
        ALOGW("Failed to obtain transport type for %s/%s: %s",
              fqName.c_str(), instance.c_str(), transport.description().c_str());
        return false;
    }
    return transport != Transport::EMPTY;
}

bool hasHalService(const InterfaceName& interface, const AudioHalVersionInfo& version) {
    auto halType = version.getType();
    if (halType == AudioHalVersionInfo::Type::AIDL) {
        return hasAidlHalService(interface, version);
    } else if (halType == AudioHalVersionInfo::Type::HIDL) {
        return hasHidlHalService(interface, version);
    } else {
        ALOGE("HalType not supported %s", version.toString().c_str());
        return false;
    }
}

}  // namespace

void *createPreferredImpl(bool isDevice) {
    auto findMostRecentVersion = [](const auto& iMap) {
        return std::find_if(sAudioHALVersions.begin(), sAudioHALVersions.end(),
                            [iMap](const auto& v) {
                                auto iface = iMap.find(v.getType());
                                return hasHalService(iface->second, v);
                            });
    };

    auto interfaceMap = isDevice ? sDevicesHALInterfaces : sEffectsHALInterfaces;
    auto siblingInterfaceMap = isDevice ? sEffectsHALInterfaces : sDevicesHALInterfaces;
    auto ifaceVersionIt = findMostRecentVersion(interfaceMap);
    auto siblingVersionIt = findMostRecentVersion(siblingInterfaceMap);
    if (ifaceVersionIt != sAudioHALVersions.end() && siblingVersionIt != sAudioHALVersions.end() &&
        // same HAL type (HIDL/AIDL) and same major version
        ifaceVersionIt->getType() == siblingVersionIt->getType() &&
        ifaceVersionIt->getMajorVersion() == siblingVersionIt->getMajorVersion()) {
        void* rawInterface;
        if (createHalService(std::max(*ifaceVersionIt, *siblingVersionIt), isDevice,
                             &rawInterface)) {
            return rawInterface;
        } else {
            ALOGE("Failed to create HAL services with major %s, sibling %s!",
                  ifaceVersionIt->toString().c_str(), siblingVersionIt->toString().c_str());
        }
    } else {
        ALOGE("Found no HAL version, main(%s) %s %s!", isDevice ? "Device" : "Effect",
              (ifaceVersionIt == sAudioHALVersions.end()) ? "null"
                                                          : ifaceVersionIt->toString().c_str(),
              (siblingVersionIt == sAudioHALVersions.end()) ? "null"
                                                            : siblingVersionIt->toString().c_str());
    }
    return nullptr;
}

}  // namespace android::detail
