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

#ifndef ANDROID_HARDWARE_EFFECT_HAL_LOCAL_H
#define ANDROID_HARDWARE_EFFECT_HAL_LOCAL_H

#include "EffectHalInterface.h"

namespace android {

class EffectHalLocal : public EffectHalInterface
{
  public:
    // The destructor automatically releases the effect.
    virtual ~EffectHalLocal();

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

    // FIXME: Remove after converting the main audio HAL
    effect_handle_t handle() const { return mHandle; }

  private:
    effect_handle_t mHandle;

    friend class EffectsFactoryHalLocal;

    // Can not be constructed directly by clients.
    explicit EffectHalLocal(effect_handle_t handle);
};

} // namespace android

#endif // ANDROID_HARDWARE_EFFECT_HAL_LOCAL_H
