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

#include <string.h>
#include <set>

#define LOG_TAG "DevicesFactoryHalHidl"
//#define LOG_NDEBUG 0

#include <android/hidl/manager/1.0/IServiceManager.h>
#include <android/hidl/manager/1.0/IServiceNotification.h>
#include PATH(android/hardware/audio/FILE_VERSION/IDevice.h)
#include <media/audiohal/hidl/HalDeathHandler.h>
#include <utils/Log.h>

#include "ConversionHelperHidl.h"
#include "DeviceHalHidl.h"
#include "DevicesFactoryHalHidl.h"

using ::android::hardware::audio::CPP_VERSION::IDevice;
using ::android::hardware::audio::CPP_VERSION::Result;
using ::android::hardware::Return;
using ::android::hardware::Void;
using ::android::hidl::manager::V1_0::IServiceManager;
using ::android::hidl::manager::V1_0::IServiceNotification;

namespace android {
namespace CPP_VERSION {

class ServiceNotificationListener : public IServiceNotification {
  public:
    explicit ServiceNotificationListener(sp<DevicesFactoryHalHidl> factory)
            : mFactory(factory) {}

    Return<void> onRegistration(const hidl_string& /*fully_qualified_name*/,
            const hidl_string& instance_name,
            bool /*pre_existing*/) override {
        if (static_cast<std::string>(instance_name) == "default") return Void();
        sp<DevicesFactoryHalHidl> factory = mFactory.promote();
        if (!factory) return Void();
        sp<IDevicesFactory> halFactory = IDevicesFactory::getService(instance_name);
        if (halFactory) {
            factory->addDeviceFactory(halFactory, true /*needToNotify*/);
        }
        return Void();
    }

  private:
    wp<DevicesFactoryHalHidl> mFactory;
};

DevicesFactoryHalHidl::DevicesFactoryHalHidl(sp<IDevicesFactory> devicesFactory) {
    ALOG_ASSERT(devicesFactory != nullptr, "Provided default IDevicesFactory service is NULL");
    addDeviceFactory(devicesFactory, false /*needToNotify*/);
}

void DevicesFactoryHalHidl::onFirstRef() {
    sp<IServiceManager> sm = IServiceManager::getService();
    ALOG_ASSERT(sm != nullptr, "Hardware service manager is not running");
    sp<ServiceNotificationListener> listener = new ServiceNotificationListener(this);
    Return<bool> result = sm->registerForNotifications(
            IDevicesFactory::descriptor, "", listener);
    if (result.isOk()) {
        ALOGE_IF(!static_cast<bool>(result),
                "Hardware service manager refused to register listener");
    } else {
        ALOGE("Failed to register for hardware service manager notifications: %s",
                result.description().c_str());
    }
}

#if MAJOR_VERSION == 2
static IDevicesFactory::Device idFromHal(const char *name, status_t* status) {
    *status = OK;
    if (strcmp(name, AUDIO_HARDWARE_MODULE_ID_PRIMARY) == 0) {
        return IDevicesFactory::Device::PRIMARY;
    } else if(strcmp(name, AUDIO_HARDWARE_MODULE_ID_A2DP) == 0) {
        return IDevicesFactory::Device::A2DP;
    } else if(strcmp(name, AUDIO_HARDWARE_MODULE_ID_USB) == 0) {
        return IDevicesFactory::Device::USB;
    } else if(strcmp(name, AUDIO_HARDWARE_MODULE_ID_REMOTE_SUBMIX) == 0) {
        return IDevicesFactory::Device::R_SUBMIX;
    } else if(strcmp(name, AUDIO_HARDWARE_MODULE_ID_STUB) == 0) {
        return IDevicesFactory::Device::STUB;
    }
    ALOGE("Invalid device name %s", name);
    *status = BAD_VALUE;
    return {};
}
#elif MAJOR_VERSION >= 4
static const char* idFromHal(const char *name, status_t* status) {
    *status = OK;
    return name;
}
#endif

status_t DevicesFactoryHalHidl::openDevice(const char *name, sp<DeviceHalInterface> *device) {
    auto factories = copyDeviceFactories();
    if (factories.empty()) return NO_INIT;
    status_t status;
    auto hidlId = idFromHal(name, &status);
    if (status != OK) return status;
    Result retval = Result::NOT_INITIALIZED;
    for (const auto& factory : factories) {
        Return<void> ret = factory->openDevice(
                hidlId,
                [&](Result r, const sp<IDevice>& result) {
                    retval = r;
                    if (retval == Result::OK) {
                        *device = new DeviceHalHidl(result);
                    }
                });
        if (!ret.isOk()) return FAILED_TRANSACTION;
        switch (retval) {
            // Device was found and was initialized successfully.
            case Result::OK: return OK;
            // Device was found but failed to initalize.
            case Result::NOT_INITIALIZED: return NO_INIT;
            // Otherwise continue iterating.
            default: ;
        }
    }
    ALOGW("The specified device name is not recognized: \"%s\"", name);
    return BAD_VALUE;
}

status_t DevicesFactoryHalHidl::getHalPids(std::vector<pid_t> *pids) {
    std::set<pid_t> pidsSet;
    auto factories = copyDeviceFactories();
    for (const auto& factory : factories) {
        using ::android::hidl::base::V1_0::DebugInfo;

        DebugInfo debugInfo;
        auto ret = factory->getDebugInfo([&] (const auto &info) {
               debugInfo = info;
            });
        if (!ret.isOk()) {
           return INVALID_OPERATION;
        }
        if (debugInfo.pid == (int)IServiceManager::PidConstant::NO_PID) {
            continue;
        }
        pidsSet.insert(debugInfo.pid);
    }

    *pids = {pidsSet.begin(), pidsSet.end()};
    return NO_ERROR;
}

status_t DevicesFactoryHalHidl::setCallbackOnce(sp<DevicesFactoryHalCallback> callback) {
    ALOG_ASSERT(callback != nullptr);
    bool needToCallCallback = false;
    {
        std::lock_guard<std::mutex> lock(mLock);
        if (mCallback.unsafe_get()) return INVALID_OPERATION;
        mCallback = callback;
        if (mHaveUndeliveredNotifications) {
            needToCallCallback = true;
            mHaveUndeliveredNotifications = false;
        }
    }
    if (needToCallCallback) {
        callback->onNewDevicesAvailable();
    }
    return NO_ERROR;
}

void DevicesFactoryHalHidl::addDeviceFactory(sp<IDevicesFactory> factory, bool needToNotify) {
    // It is assumed that the DevicesFactoryHalInterface instance is owned
    // by AudioFlinger and thus have the same lifespan.
    factory->linkToDeath(HalDeathHandler::getInstance(), 0 /*cookie*/);
    sp<DevicesFactoryHalCallback> callback;
    {
        std::lock_guard<std::mutex> lock(mLock);
        mDeviceFactories.push_back(factory);
        if (needToNotify) {
            callback = mCallback.promote();
            if (!callback) {
                mHaveUndeliveredNotifications = true;
            }
        }
    }
    if (callback) {
        callback->onNewDevicesAvailable();
    }
}

std::vector<sp<IDevicesFactory>> DevicesFactoryHalHidl::copyDeviceFactories() {
    std::lock_guard<std::mutex> lock(mLock);
    return mDeviceFactories;
}

} // namespace CPP_VERSION
} // namespace android
