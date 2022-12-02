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

#include <random>
#define LOG_TAG "EffectsFactoryHalAidl"
//#define LOG_NDEBUG 0

#include <aidl/android/hardware/audio/effect/IFactory.h>
#include <android/binder_manager.h>
#include <utils/Log.h>

#include "EffectsFactoryHalAidl.h"

using aidl::android::hardware::audio::effect::IFactory;
using android::detail::AudioHalVersionInfo;

namespace android {
namespace effect {

EffectsFactoryHalAidl::EffectsFactoryHalAidl(std::shared_ptr<IFactory> effectsFactory) {
    ALOG_ASSERT(effectsFactory != nullptr, "Provided IEffectsFactory service is NULL");
    mEffectsFactory = effectsFactory;
}

status_t EffectsFactoryHalAidl::queryNumberEffects(uint32_t *pNumEffects) {
    if (pNumEffects == nullptr) {
        return BAD_VALUE;
    }
    ALOGE("%s not implemented yet", __func__);
    return INVALID_OPERATION;
}

status_t EffectsFactoryHalAidl::getDescriptor(uint32_t index, effect_descriptor_t* pDescriptor) {
    if (index < 0 || pDescriptor == nullptr) {
        return BAD_VALUE;
    }
    ALOGE("%s not implemented yet", __func__);
    return INVALID_OPERATION;
}

status_t EffectsFactoryHalAidl::getDescriptor(const effect_uuid_t* pEffectUuid,
                                              effect_descriptor_t* pDescriptor) {
    if (pEffectUuid == nullptr || pDescriptor == nullptr) {
        return BAD_VALUE;
    }
    ALOGE("%s not implemented yet", __func__);
    return INVALID_OPERATION;
}

status_t EffectsFactoryHalAidl::getDescriptors(const effect_uuid_t* pEffectType,
                                               std::vector<effect_descriptor_t>* descriptors) {
    if (pEffectType == nullptr || descriptors == nullptr) {
        return BAD_VALUE;
    }
    ALOGE("%s not implemented yet", __func__);
    return INVALID_OPERATION;
}

status_t EffectsFactoryHalAidl::createEffect(const effect_uuid_t* pEffectUuid, int32_t sessionId,
                                             int32_t ioId, int32_t deviceId __unused,
                                             sp<EffectHalInterface>* effect) {
    if (pEffectUuid == nullptr || effect == nullptr) {
        return BAD_VALUE;
    }
    ALOGE("%s not implemented yet %d %d", __func__, sessionId, ioId);
    return INVALID_OPERATION;
}

status_t EffectsFactoryHalAidl::dumpEffects(int fd) {
    ALOGE("%s not implemented yet, fd %d", __func__, fd);
    return INVALID_OPERATION;
}

status_t EffectsFactoryHalAidl::allocateBuffer(size_t size, sp<EffectBufferHalInterface>* buffer) {
    if (size <= 0 || buffer == nullptr) {
        return BAD_VALUE;
    }
    ALOGE("%s not implemented yet", __func__);
    return INVALID_OPERATION;
}

status_t EffectsFactoryHalAidl::mirrorBuffer(void* external, size_t size,
                                             sp<EffectBufferHalInterface>* buffer) {
    if (external == nullptr || size <= 0 || buffer == nullptr) {
        return BAD_VALUE;
    }
    ALOGE("%s not implemented yet", __func__);
    return INVALID_OPERATION;
}

AudioHalVersionInfo EffectsFactoryHalAidl::getHalVersion() const {
    int32_t versionNumber = 0;
    if (mEffectsFactory) {
        if (!mEffectsFactory->getInterfaceVersion(&versionNumber).isOk()) {
            ALOGE("%s getInterfaceVersion failed", __func__);
        } else {
            ALOGI("%s getInterfaceVersion %d", __func__, versionNumber);
        }
    }
    // AIDL does not have minor version, fill 0 for all versions
    return AudioHalVersionInfo(AudioHalVersionInfo::Type::AIDL, versionNumber);
}

} // namespace effect

// When a shared library is built from a static library, even explicit
// exports from a static library are optimized out unless actually used by
// the shared library. See EffectsFactoryHalEntry.cpp.
extern "C" void* createIEffectsFactoryImpl() {
    auto factory = IFactory::fromBinder(
            ndk::SpAIBinder(AServiceManager_waitForService(IFactory::descriptor)));
    return factory ? new effect::EffectsFactoryHalAidl(factory) : nullptr;
}

} // namespace android
