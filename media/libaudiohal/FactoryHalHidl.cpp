/*
 * Copyright (C) 2020 The Android Open Source Project
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

#define LOG_TAG "FactoryHalHidl"

#include <media/audiohal/FactoryHalHidl.h>

#include <dlfcn.h>

#include <android/hidl/manager/1.0/IServiceManager.h>
#include <hidl/ServiceManagement.h>
#include <hidl/Status.h>
#include <utils/Log.h>

namespace android::detail {

namespace {
/** Supported HAL versions, in order of preference.
 */
const char* sAudioHALVersions[] = {
    "6.0",
    "5.0",
    "4.0",
    "2.0",
    nullptr
};

bool createHalService(const std::string& version, const std::string& interface,
        void** rawInterface) {
    const std::string libName = "libaudiohal@" + version + ".so";
    const std::string factoryFunctionName = "create" + interface;
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

bool hasHalService(const std::string& package, const std::string& version,
        const std::string& interface) {
    using ::android::hidl::manager::V1_0::IServiceManager;
    sp<IServiceManager> sm = ::android::hardware::defaultServiceManager();
    if (!sm) {
        ALOGE("Failed to obtain HIDL ServiceManager");
        return false;
    }
    // Since audio HAL doesn't support multiple clients, avoid instantiating
    // the interface right away. Instead, query the transport type for it.
    using ::android::hardware::Return;
    using Transport = IServiceManager::Transport;
    const std::string fqName = package + "@" + version + "::" + interface;
    const std::string instance = "default";
    Return<Transport> transport = sm->getTransport(fqName, instance);
    if (!transport.isOk()) {
        ALOGE("Failed to obtain transport type for %s/%s: %s",
                fqName.c_str(), instance.c_str(), transport.description().c_str());
        return false;
    }
    return transport != Transport::EMPTY;
}

}  // namespace

void* createPreferredImpl(const std::string& package, const std::string& interface) {
    for (auto version = detail::sAudioHALVersions; version != nullptr; ++version) {
        void* rawInterface = nullptr;
        if (hasHalService(package, *version, interface)
                && createHalService(*version, interface, &rawInterface)) {
            return rawInterface;
        }
    }
    return nullptr;
}

}  // namespace android::detail
