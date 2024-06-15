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

#include <algorithm>
#include <map>
#include <memory>
#include <mutex>
#include <string>

#define LOG_TAG "DevicesFactoryHalAidl"
//#define LOG_NDEBUG 0

#include <aidl/android/hardware/audio/core/IModule.h>
#include <aidl/android/media/audio/BnHalAdapterVendorExtension.h>
#include <android/binder_manager.h>
#include <cutils/properties.h>
#include <media/AidlConversionNdkCpp.h>
#include <media/AidlConversionUtil.h>
#include <utils/Log.h>

#include "DeviceHalAidl.h"
#include "DevicesFactoryHalAidl.h"

using aidl::android::aidl_utils::statusTFromBinderStatus;
using aidl::android::hardware::audio::core::IConfig;
using aidl::android::hardware::audio::core::IModule;
using aidl::android::hardware::audio::core::SurroundSoundConfig;
using aidl::android::hardware::audio::core::VendorParameter;
using aidl::android::media::audio::common::AudioHalEngineConfig;
using aidl::android::media::audio::IHalAdapterVendorExtension;
using android::detail::AudioHalVersionInfo;

namespace android {

namespace {

ConversionResult<media::SurroundSoundConfig::SurroundFormatFamily>
ndk2cpp_SurroundSoundConfigFormatFamily(const SurroundSoundConfig::SurroundFormatFamily& ndk) {
    media::SurroundSoundConfig::SurroundFormatFamily cpp;
    cpp.primaryFormat = VALUE_OR_RETURN(ndk2cpp_AudioFormatDescription(ndk.primaryFormat));
    cpp.subFormats = VALUE_OR_RETURN(::aidl::android::convertContainer<std::vector<
            media::audio::common::AudioFormatDescription>>(ndk.subFormats,
                    ndk2cpp_AudioFormatDescription));
    return cpp;
}

ConversionResult<media::SurroundSoundConfig>
ndk2cpp_SurroundSoundConfig(const SurroundSoundConfig& ndk) {
    media::SurroundSoundConfig cpp;
    cpp.formatFamilies = VALUE_OR_RETURN(::aidl::android::convertContainer<std::vector<
            media::SurroundSoundConfig::SurroundFormatFamily>>(ndk.formatFamilies,
                    ndk2cpp_SurroundSoundConfigFormatFamily));
    return cpp;
}

class HalAdapterVendorExtensionWrapper :
            public ::aidl::android::media::audio::BnHalAdapterVendorExtension {
  private:
    template<typename F>
    ndk::ScopedAStatus callWithRetryOnCrash(F method) {
        ndk::ScopedAStatus status = ndk::ScopedAStatus::ok();
        for (auto service = getService(); service != nullptr; service = getService(true)) {
            status = method(service);
            if (status.getStatus() != STATUS_DEAD_OBJECT) break;
        }
        return status;
    }

    ndk::ScopedAStatus parseVendorParameterIds(ParameterScope in_scope,
                                               const std::string& in_rawKeys,
                                               std::vector<std::string>* _aidl_return) override {
        return callWithRetryOnCrash([&](auto service) {
            return service->parseVendorParameterIds(in_scope, in_rawKeys, _aidl_return);
        });
    }

    ndk::ScopedAStatus parseVendorParameters(
            ParameterScope in_scope, const std::string& in_rawKeysAndValues,
            std::vector<VendorParameter>* out_syncParameters,
            std::vector<VendorParameter>* out_asyncParameters) override {
        return callWithRetryOnCrash([&](auto service) {
            return service->parseVendorParameters(in_scope, in_rawKeysAndValues,
                    out_syncParameters, out_asyncParameters);
        });
    }

    ndk::ScopedAStatus parseBluetoothA2dpReconfigureOffload(
            const std::string& in_rawValue, std::vector<VendorParameter>* _aidl_return) override {
        return callWithRetryOnCrash([&](auto service) {
            return service->parseBluetoothA2dpReconfigureOffload(in_rawValue, _aidl_return);
        });
    }

    ndk::ScopedAStatus parseBluetoothLeReconfigureOffload(const std::string& in_rawValue,
            std::vector<VendorParameter>* _aidl_return) override {
        return callWithRetryOnCrash([&](auto service) {
            return service->parseBluetoothLeReconfigureOffload(in_rawValue, _aidl_return);
        });
    }

    ndk::ScopedAStatus processVendorParameters(ParameterScope in_scope,
                                               const std::vector<VendorParameter>& in_parameters,
                                               std::string* _aidl_return) override {
        return callWithRetryOnCrash([&](auto service) {
            return service->processVendorParameters(in_scope, in_parameters, _aidl_return);
        });
    }

    std::shared_ptr<IHalAdapterVendorExtension> getService(bool reset = false) {
        std::lock_guard l(mLock);
        if (reset || !mVendorExt.has_value()) {
            if (property_get_bool("ro.audio.ihaladaptervendorextension_enabled", false)) {
                auto serviceName = std::string(IHalAdapterVendorExtension::descriptor) + "/default";
                mVendorExt = std::shared_ptr<IHalAdapterVendorExtension>(
                        IHalAdapterVendorExtension::fromBinder(ndk::SpAIBinder(
                                        AServiceManager_waitForService(serviceName.c_str()))));
            } else {
                mVendorExt = nullptr;
            }
        }
        return mVendorExt.value();
    }

    std::mutex mLock;
    std::optional<std::shared_ptr<::aidl::android::media::audio::IHalAdapterVendorExtension>>
            mVendorExt GUARDED_BY(mLock);
};

}  // namespace

DevicesFactoryHalAidl::DevicesFactoryHalAidl(std::shared_ptr<IConfig> config)
        : mConfig(std::move(config)),
          mVendorExt(ndk::SharedRefBase::make<HalAdapterVendorExtensionWrapper>()) {
}

status_t DevicesFactoryHalAidl::getDeviceNames(std::vector<std::string> *names) {
    if (names == nullptr) {
        return BAD_VALUE;
    }
    AServiceManager_forEachDeclaredInstance(IModule::descriptor, static_cast<void*>(names),
            [](const char* instance, void* context) {
                if (strcmp(instance, "default") == 0) instance = "primary";
                static_cast<decltype(names)>(context)->push_back(instance);
            });
    std::sort(names->begin(), names->end(), [](const std::string& lhs,
                    const std::string& rhs) {
        // This order corresponds to the canonical order of modules as specified in
        // the reference 'audio_policy_configuration_7_0.xml' file.
        static const std::map<std::string, int> kPriorities{
            { "primary", 0 }, { "a2dp", 1 }, { "usb", 2 }, { "r_submix", 3 },
            { "bluetooth", 4 }, { "hearing_aid", 5 }, { "msd", 6 }, { "stub", 7 }
        };
        auto lhsIt = kPriorities.find(lhs);
        auto rhsIt = kPriorities.find(rhs);
        if (lhsIt != kPriorities.end() && rhsIt != kPriorities.end()) {
            return lhsIt->second < rhsIt->second;
        }
        return lhsIt != kPriorities.end();
    });
    return OK;
}

// Opens a device with the specified name. To close the device, it is
// necessary to release references to the returned object.
status_t DevicesFactoryHalAidl::openDevice(const char *name, sp<DeviceHalInterface> *device) {
    if (name == nullptr || device == nullptr) {
        return BAD_VALUE;
    }
    std::shared_ptr<IModule> service;
    if (strcmp(name, "primary") == 0) name = "default";
    auto serviceName = std::string(IModule::descriptor) + "/" + name;
    service = IModule::fromBinder(
            ndk::SpAIBinder(AServiceManager_waitForService(serviceName.c_str())));
    if (service == nullptr) {
        ALOGE("%s fromBinder %s failed", __func__, serviceName.c_str());
        return NO_INIT;
    }
    *device = sp<DeviceHalAidl>::make(name, service, mVendorExt);
    return OK;
}

status_t DevicesFactoryHalAidl::setCallbackOnce(sp<DevicesFactoryHalCallback> callback) {
    // Dynamic registration of module instances is not supported. The functionality
    // in the audio server which is related to this callback can be removed together
    // with HIDL support.
    ALOG_ASSERT(callback != nullptr);
    if (callback != nullptr) {
        callback->onNewDevicesAvailable();
    }
    return NO_ERROR;
}

AudioHalVersionInfo DevicesFactoryHalAidl::getHalVersion() const {
    int32_t versionNumber = 0;
    if (ndk::ScopedAStatus status = mConfig->getInterfaceVersion(&versionNumber); !status.isOk()) {
        ALOGE("%s getInterfaceVersion failed: %s", __func__, status.getDescription().c_str());
    }
    // AIDL does not have minor version, fill 0 for all versions
    return AudioHalVersionInfo(AudioHalVersionInfo::Type::AIDL, versionNumber);
}

status_t DevicesFactoryHalAidl::getSurroundSoundConfig(media::SurroundSoundConfig *config) {
    SurroundSoundConfig ndkConfig;
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mConfig->getSurroundSoundConfig(&ndkConfig)));
    *config = VALUE_OR_RETURN_STATUS(ndk2cpp_SurroundSoundConfig(ndkConfig));
    return OK;
}

status_t DevicesFactoryHalAidl::getEngineConfig(
        media::audio::common::AudioHalEngineConfig *config) {
    AudioHalEngineConfig ndkConfig;
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mConfig->getEngineConfig(&ndkConfig)));
    *config = VALUE_OR_RETURN_STATUS(ndk2cpp_AudioHalEngineConfig(ndkConfig));
    return OK;
}

// Main entry-point to the shared library.
extern "C" __attribute__((visibility("default"))) void* createIDevicesFactoryImpl() {
    auto serviceName = std::string(IConfig::descriptor) + "/default";
    auto service = IConfig::fromBinder(
            ndk::SpAIBinder(AServiceManager_waitForService(serviceName.c_str())));
    if (!service) {
        ALOGE("%s binder service %s not exist", __func__, serviceName.c_str());
        return nullptr;
    }
    return new DevicesFactoryHalAidl(service);
}

} // namespace android
