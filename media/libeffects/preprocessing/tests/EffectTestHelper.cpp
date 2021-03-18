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

void EffectTestHelper::createEffect() {
    int status = AUDIO_EFFECT_LIBRARY_INFO_SYM.create_effect(mUuid, 1, 1, &mEffectHandle);
    ASSERT_EQ(status, 0) << "create_effect returned an error " << status;
}

void EffectTestHelper::releaseEffect() {
    int status = AUDIO_EFFECT_LIBRARY_INFO_SYM.release_effect(mEffectHandle);
    ASSERT_EQ(status, 0) << "release_effect returned an error " << status;
}

void EffectTestHelper::setConfig(bool configReverse) {
    effect_config_t config{};
    config.inputCfg.samplingRate = config.outputCfg.samplingRate = mSampleRate;
    config.inputCfg.channels = config.outputCfg.channels = mChMask;
    config.inputCfg.format = config.outputCfg.format = AUDIO_FORMAT_PCM_16_BIT;

    int reply = 0;
    uint32_t replySize = sizeof(reply);

    int status = (*mEffectHandle)
                         ->command(mEffectHandle, EFFECT_CMD_SET_CONFIG, sizeof(effect_config_t),
                                   &config, &replySize, &reply);
    ASSERT_EQ(status, 0) << "set_config returned an error " << status;
    ASSERT_EQ(reply, 0) << "set_config reply non zero " << reply;

    if (configReverse) {
        int status = (*mEffectHandle)
                             ->command(mEffectHandle, EFFECT_CMD_SET_CONFIG_REVERSE,
                                       sizeof(effect_config_t), &config, &replySize, &reply);
        ASSERT_EQ(status, 0) << "set_config_reverse returned an error " << status;
        ASSERT_EQ(reply, 0) << "set_config_reverse reply non zero " << reply;
    }

    status = (*mEffectHandle)
                     ->command(mEffectHandle, EFFECT_CMD_ENABLE, 0, nullptr, &replySize, &reply);
    ASSERT_EQ(status, 0) << "cmd_enable returned an error " << status;
    ASSERT_EQ(reply, 0) << "cmd_enable reply non zero " << reply;
}

void EffectTestHelper::setParam(uint32_t type, uint32_t value) {
    int reply = 0;
    uint32_t replySize = sizeof(reply);
    uint32_t paramData[2] = {type, value};
    auto effectParam = (effect_param_t*)malloc(sizeof(effect_param_t) + sizeof(paramData));
    memcpy(&effectParam->data[0], &paramData[0], sizeof(paramData));
    effectParam->psize = sizeof(paramData[0]);
    effectParam->vsize = sizeof(paramData[1]);
    int status = (*mEffectHandle)
                         ->command(mEffectHandle, EFFECT_CMD_SET_PARAM,
                                   sizeof(effect_param_t) + sizeof(paramData), effectParam,
                                   &replySize, &reply);
    free(effectParam);
    ASSERT_EQ(status, 0) << "set_param returned an error " << status;
    ASSERT_EQ(reply, 0) << "set_param reply non zero " << reply;
}

void EffectTestHelper::process(int16_t* input, int16_t* output, bool setAecEchoDelay) {
    audio_buffer_t inBuffer = {.frameCount = mFrameCount, .s16 = input};
    audio_buffer_t outBuffer = {.frameCount = mFrameCount, .s16 = output};
    for (size_t i = 0; i < mLoopCount; i++) {
        if (setAecEchoDelay) ASSERT_NO_FATAL_FAILURE(setParam(AEC_PARAM_ECHO_DELAY, kAECDelay));
        int status = (*mEffectHandle)->process(mEffectHandle, &inBuffer, &outBuffer);
        ASSERT_EQ(status, 0) << "process returned an error " << status;

        inBuffer.s16 += mFrameCount * mChannelCount;
        outBuffer.s16 += mFrameCount * mChannelCount;
    }
}

void EffectTestHelper::process_reverse(int16_t* farInput, int16_t* output) {
    audio_buffer_t farInBuffer = {.frameCount = mFrameCount, .s16 = farInput};
    audio_buffer_t outBuffer = {.frameCount = mFrameCount, .s16 = output};
    for (size_t i = 0; i < mLoopCount; i++) {
        int status = (*mEffectHandle)->process_reverse(mEffectHandle, &farInBuffer, &outBuffer);
        ASSERT_EQ(status, 0) << "process returned an error " << status;

        farInBuffer.s16 += mFrameCount * mChannelCount;
        outBuffer.s16 += mFrameCount * mChannelCount;
    }
}
