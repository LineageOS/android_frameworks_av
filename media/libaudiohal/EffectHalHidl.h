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

#ifndef ANDROID_HARDWARE_EFFECT_HAL_HIDL_H
#define ANDROID_HARDWARE_EFFECT_HAL_HIDL_H

#include <android/hardware/audio/effect/2.0/IEffect.h>
#include <media/audiohal/EffectHalInterface.h>
#include <system/audio_effect.h>

using ::android::hardware::audio::effect::V2_0::EffectDescriptor;
using ::android::hardware::audio::effect::V2_0::IEffect;

namespace android {

class EffectHalHidl : public EffectHalInterface
{
  public:
    // Effect process function. Takes input samples as specified
    // in input buffer descriptor and output processed samples as specified
    // in output buffer descriptor.
    virtual status_t process(audio_buffer_t *inBuffer, audio_buffer_t *outBuffer);

    // Process reverse stream function. This function is used to pass
    // a reference stream to the effect engine.
    virtual status_t processReverse(audio_buffer_t *inBuffer, audio_buffer_t *outBuffer);

    // Send a command and receive a response to/from effect engine.
    virtual status_t command(uint32_t cmdCode, uint32_t cmdSize, void *pCmdData,
            uint32_t *replySize, void *pReplyData);

    // Returns the effect descriptor.
    virtual status_t getDescriptor(effect_descriptor_t *pDescriptor);

    uint64_t effectId() const { return mEffectId; }

    static void effectDescriptorToHal(
            const EffectDescriptor& descriptor, effect_descriptor_t* halDescriptor);

  private:
    friend class EffectsFactoryHalHidl;
    sp<IEffect> mEffect;
    const uint64_t mEffectId;

    static status_t analyzeResult(const hardware::audio::effect::V2_0::Result& result);

    // Can not be constructed directly by clients.
    EffectHalHidl(const sp<IEffect>& effect, uint64_t effectId);

    // The destructor automatically releases the effect.
    virtual ~EffectHalHidl();
};

} // namespace android

#endif // ANDROID_HARDWARE_EFFECT_HAL_HIDL_H
