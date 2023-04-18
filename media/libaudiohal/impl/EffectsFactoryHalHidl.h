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

#pragma once

#include <memory>
#include <vector>

#include PATH(android/hardware/audio/effect/FILE_VERSION/IEffectsFactory.h)
#include <media/audiohal/EffectsFactoryHalInterface.h>

#include "EffectConversionHelperHidl.h"

namespace android {
namespace effect {

using ::android::hardware::hidl_vec;
using namespace ::android::hardware::audio::effect::CPP_VERSION;

class EffectDescriptorCache;

class EffectsFactoryHalHidl final : public EffectsFactoryHalInterface,
                                    public EffectConversionHelperHidl {
  public:
    EffectsFactoryHalHidl(sp<IEffectsFactory> effectsFactory);

    // Returns the number of different effects in all loaded libraries.
    status_t queryNumberEffects(uint32_t *pNumEffects) override;

    // Returns a descriptor of the next available effect.
    status_t getDescriptor(uint32_t index, effect_descriptor_t* pDescriptor) override;

    status_t getDescriptor(const effect_uuid_t* pEffectUuid,
                           effect_descriptor_t* pDescriptor) override;

    status_t getDescriptors(const effect_uuid_t* pEffectType,
                            std::vector<effect_descriptor_t>* descriptors) override;

    // Creates an effect engine of the specified type.
    // To release the effect engine, it is necessary to release references
    // to the returned effect object.
    status_t createEffect(const effect_uuid_t* pEffectUuid, int32_t sessionId, int32_t ioId,
                          int32_t deviceId, sp<EffectHalInterface>* effect) override;

    status_t dumpEffects(int fd) override;

    status_t allocateBuffer(size_t size, sp<EffectBufferHalInterface>* buffer) override;
    status_t mirrorBuffer(void* external, size_t size,
                          sp<EffectBufferHalInterface>* buffer) override;

    android::detail::AudioHalVersionInfo getHalVersion() const override;

    std::shared_ptr<const effectsConfig::Processings> getProcessings() const override;

    ::android::error::Result<size_t> getSkippedElements() const override;

  private:
    const sp<IEffectsFactory> mEffectsFactory;
    const std::unique_ptr<EffectDescriptorCache> mCache;
    /**
     * Configuration file parser result, used by getProcessings() and getConfigParseResult().
     * This struct holds the result of parsing a configuration file. The result includes the parsed
     * configuration data, as well as any errors that occurred during parsing.
     */
    const effectsConfig::ParsingResult mParsingResult;
};

} // namespace effect
} // namespace android
