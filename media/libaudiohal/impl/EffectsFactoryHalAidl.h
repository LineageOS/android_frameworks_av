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
#include <memory>
#include <mutex>

#include <aidl/android/hardware/audio/effect/IFactory.h>
#include <android-base/thread_annotations.h>
#include <media/audiohal/EffectsFactoryHalInterface.h>
#include <system/thread_defs.h>

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

    // for TIME_CHECK
    const std::string getClassName() const { return "EffectHalAidl"; }

  private:
    std::mutex mLock;
    const std::shared_ptr<IFactory> mFactory;
    uint64_t mEffectIdCounter GUARDED_BY(mLock) = 0; // Align with HIDL (0 is INVALID_ID)
    std::unique_ptr<std::vector<Descriptor>> mDescList GUARDED_BY(mLock) = nullptr;
    const detail::AudioHalVersionInfo mHalVersion;

    virtual ~EffectsFactoryHalAidl() = default;
    status_t queryEffectList_l() REQUIRES(mLock);
    status_t getHalDescriptorWithImplUuid_l(
            const aidl::android::media::audio::common::AudioUuid& uuid,
            effect_descriptor_t* pDescriptor) REQUIRES(mLock);
    status_t getHalDescriptorWithTypeUuid_l(
            const aidl::android::media::audio::common::AudioUuid& type,
            std::vector<effect_descriptor_t>* descriptors) REQUIRES(mLock);
};

} // namespace effect
} // namespace android
