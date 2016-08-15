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

#include <media/EffectsFactoryApi.h>
#include <utils/Log.h>

#include "EffectHalLocal.h"

namespace android {

EffectHalLocal::EffectHalLocal(effect_handle_t handle)
        : mHandle(handle) {
}

EffectHalLocal::~EffectHalLocal() {
    int status = EffectRelease(mHandle);
    if (status != 0) {
        ALOGW("Error releasing effect %p: %s", mHandle, strerror(-status));
    }
}

status_t EffectHalLocal::process(audio_buffer_t *inBuffer, audio_buffer_t *outBuffer) {
    return (*mHandle)->process(mHandle, inBuffer, outBuffer);
}

status_t EffectHalLocal::processReverse(audio_buffer_t *inBuffer, audio_buffer_t *outBuffer) {
    return (*mHandle)->process_reverse(mHandle, inBuffer, outBuffer);
}

status_t EffectHalLocal::command(uint32_t cmdCode, uint32_t cmdSize, void *pCmdData,
        uint32_t *replySize, void *pReplyData) {
    return (*mHandle)->command(mHandle, cmdCode, cmdSize, pCmdData, replySize, pReplyData);
}

status_t EffectHalLocal::getDescriptor(effect_descriptor_t *pDescriptor) {
    return (*mHandle)->get_descriptor(mHandle, pDescriptor);
}

} // namespace android
