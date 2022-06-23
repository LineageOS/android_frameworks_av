/*
 * Copyright 2021 The Android Open Source Project
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

#include "EffectTestHelper.h"
extern audio_effect_library_t AUDIO_EFFECT_LIBRARY_INFO_SYM;

namespace android {

void EffectTestHelper::createEffect() {
    int status = AUDIO_EFFECT_LIBRARY_INFO_SYM.create_effect(mUuid, 1, 1, &mEffectHandle);
    ASSERT_EQ(status, 0) << "create_effect returned an error " << status;
}

void EffectTestHelper::releaseEffect() {
    int status = AUDIO_EFFECT_LIBRARY_INFO_SYM.release_effect(mEffectHandle);
    ASSERT_EQ(status, 0) << "release_effect returned an error " << status;
}

void EffectTestHelper::setConfig() {
    effect_config_t config{};
    config.inputCfg.samplingRate = config.outputCfg.samplingRate = mSampleRate;
    config.inputCfg.channels = mInChMask;
    config.outputCfg.channels = mOutChMask;
    config.inputCfg.format = config.outputCfg.format = AUDIO_FORMAT_PCM_FLOAT;

    int reply = 0;
    uint32_t replySize = sizeof(reply);
    int status = (*mEffectHandle)
                         ->command(mEffectHandle, EFFECT_CMD_SET_CONFIG, sizeof(effect_config_t),
                                   &config, &replySize, &reply);
    ASSERT_EQ(status, 0) << "set_config returned an error " << status;
    ASSERT_EQ(reply, 0) << "set_config reply non zero " << reply;

    status = (*mEffectHandle)
                     ->command(mEffectHandle, EFFECT_CMD_ENABLE, 0, nullptr, &replySize, &reply);
    ASSERT_EQ(status, 0) << "cmd_enable returned an error " << status;
    ASSERT_EQ(reply, 0) << "cmd_enable reply non zero " << reply;
}

void EffectTestHelper::process(float* input, float* output) {
    audio_buffer_t inBuffer = {.frameCount = mFrameCount, .f32 = input};
    audio_buffer_t outBuffer = {.frameCount = mFrameCount, .f32 = output};
    for (size_t i = 0; i < mLoopCount; i++) {
        int status = (*mEffectHandle)->process(mEffectHandle, &inBuffer, &outBuffer);
        ASSERT_EQ(status, 0) << "process returned an error " << status;

        inBuffer.f32 += mFrameCount * mInChannelCount;
        outBuffer.f32 += mFrameCount * mOutChannelCount;
    }
}
}  // namespace android
