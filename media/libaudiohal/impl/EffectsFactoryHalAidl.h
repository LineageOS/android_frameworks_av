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

#pragma once

#include <cstddef>
#include <list>
#include <memory>

#include <aidl/android/hardware/audio/effect/IFactory.h>
#include <aidl/android/hardware/audio/effect/Processing.h>
#include <android-base/thread_annotations.h>
#include <media/audiohal/EffectsFactoryHalInterface.h>
#include <system/thread_defs.h>

#include "EffectProxy.h"

namespace android {
namespace effect {

using namespace aidl::android::hardware::audio::effect;

class EffectsFactoryHalAidl final : public EffectsFactoryHalInterface {
  public:
    explicit EffectsFactoryHalAidl(std::shared_ptr<IFactory> effectsFactory);

    // Returns the number of different effects in all loaded libraries.
    status_t queryNumberEffects(uint32_t *pNumEffects) override;

    // Returns a descriptor of the next available effect.
    status_t getDescriptor(uint32_t index, effect_descriptor_t* pDescriptor) override;

    status_t getDescriptor(const effect_uuid_t* pEffectUuid,
                           effect_descriptor_t* pDescriptor) override;

    status_t getDescriptors(const effect_uuid_t* pEffectType,
                            std::vector<effect_descriptor_t>* descriptors) override;

    // Creates an effect engine of the specified type.
    // To release the effect engine, it is necessary to release references to the returned effect
    // object.
    status_t createEffect(const effect_uuid_t* pEffectUuid, int32_t sessionId, int32_t ioId,
                          int32_t deviceId, sp<EffectHalInterface>* effect) override;

    status_t dumpEffects(int fd) override;

    status_t allocateBuffer(size_t size, sp<EffectBufferHalInterface>* buffer) override;
    status_t mirrorBuffer(void* external, size_t size,
                          sp<EffectBufferHalInterface>* buffer) override;

    detail::AudioHalVersionInfo getHalVersion() const override;

    std::shared_ptr<const effectsConfig::Processings> getProcessings() const override;

    ::android::error::Result<size_t> getSkippedElements() const override;

  private:
    const std::shared_ptr<IFactory> mFactory;
    const detail::AudioHalVersionInfo mHalVersion;
    // Full list of HAL effect descriptors
    const std::vector<Descriptor> mHalDescList;
    // Map of proxy UUID (key) to the Descriptor of sub-effects
    const std::map<::aidl::android::media::audio::common::AudioUuid, std::vector<Descriptor>>
            mProxyUuidDescriptorMap;
    // List of effect proxy, initialize after mUuidProxyMap because it need to have all sub-effects
    const std::vector<Descriptor> mProxyDescList;
    // List of non-proxy effects
    const std::vector<Descriptor> mNonProxyDescList;
    // total number of effects including proxy effects
    const size_t mEffectCount;
    // Query result of pre and post processing from effect factory
    const std::vector<Processing> mAidlProcessings;

    // list of the EffectProxy instances
    std::list<std::shared_ptr<EffectProxy>> mProxyList;

    virtual ~EffectsFactoryHalAidl() = default;
    status_t getHalDescriptorWithImplUuid(
            const ::aidl::android::media::audio::common::AudioUuid& uuid,
            effect_descriptor_t* pDescriptor);

    status_t getHalDescriptorWithTypeUuid(
            const ::aidl::android::media::audio::common::AudioUuid& type,
            std::vector<effect_descriptor_t>* descriptors);

    bool isProxyEffect(const aidl::android::media::audio::common::AudioUuid& uuid) const;
};

} // namespace effect
} // namespace android
