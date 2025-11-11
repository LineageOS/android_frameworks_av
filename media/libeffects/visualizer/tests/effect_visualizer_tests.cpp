/*
 * Copyright (C) 2025 The Android Open Source Project
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
#include <audio_effects/effect_visualizer.h>
#include <gtest/gtest.h>
#include <log/log.h>
#include <system/audio_effects/audio_effects_test.h>

extern audio_effect_library_t AUDIO_EFFECT_LIBRARY_INFO_SYM;

using namespace android;
using namespace android::effect::utils;

static constexpr audio_channel_mask_t kChannelMasks[] = {
        AUDIO_CHANNEL_OUT_MONO,
        AUDIO_CHANNEL_OUT_STEREO,
        AUDIO_CHANNEL_OUT_5POINT1,
        AUDIO_CHANNEL_OUT_7POINT1,
        AUDIO_CHANNEL_OUT_7POINT1POINT4,
};

using VisualizerTestParam = std::tuple<int /* channel mask */>;

enum {
    CHANNEL_MASK_POSITION = 0,
};

class EffectVisualizerParamTest : public ::testing::TestWithParam<VisualizerTestParam> {
public:
    void testCapture(audio_channel_mask_t channelMask) {
        effect_handle_t handle;
        ASSERT_EQ(NO_ERROR, AUDIO_EFFECT_LIBRARY_INFO_SYM.create_effect(
                           &sVisualizerUuid, 0 /* sessionId */, 0 /* ioId */, &handle));

        constexpr uint32_t sampleRate = 48000;
        const size_t channelCount = audio_channel_count_from_out_mask(channelMask);
        ASSERT_EQ(NO_ERROR,
                effect_set_config(handle, sampleRate, channelMask, true /* accumulate */));
        ASSERT_EQ(NO_ERROR, effect_enable(handle));

        const uint32_t captureSize = 128;
        EXPECT_EQ(NO_ERROR,
                effect_set_param(handle, VISUALIZER_PARAM_CAPTURE_SIZE, captureSize));

        std::vector<uint8_t> waveform(captureSize);

        uint32_t replySize = captureSize;
        std::vector<uint8_t> replyData(replySize);

        ASSERT_EQ(NO_ERROR, (*(effect_interface_s **)handle)->command(
                handle, VISUALIZER_CMD_CAPTURE, 0 /* cmdSize */, nullptr /* pCmdData */,
                &replySize, replyData.data()));

        // 0x80 is zero for our unsigned byte.
        constexpr int kUnsignedByte0 = 0x80;
        EXPECT_EQ(kUnsignedByte0, replyData[0]);
        const bool clear = std::all_of(
                replyData.begin(), replyData.end(),
                [](uint8_t datum){ return datum == kUnsignedByte0; });
        EXPECT_TRUE(clear);

        const size_t samples = captureSize * channelCount;
        std::vector<float> inData(samples);
        std::vector<float> outData(samples);
        audio_buffer_t inBuffer{ .frameCount = captureSize, .f32 = inData.data() };
        audio_buffer_t outBuffer{ .frameCount = captureSize, .f32 = outData.data() };
        ASSERT_EQ(NO_ERROR, effect_process(handle, &inBuffer, &outBuffer));

        ASSERT_EQ(NO_ERROR, (*(effect_interface_s **)handle)->command(
                handle, VISUALIZER_CMD_CAPTURE, 0 /* cmdSize */, nullptr /* pCmdData */,
                &replySize, replyData.data()));

        EXPECT_EQ(kUnsignedByte0, replyData[0]);
        const bool capture_set_0 = std::all_of(
                replyData.begin(), replyData.end(),
                [](uint8_t datum){ return datum == kUnsignedByte0; });
        EXPECT_TRUE(capture_set_0);

        // set only the stereo channels.
        const float channelValue = 1. / 16;
        for (size_t i = 0; i < captureSize; ++i) {
            for (size_t j = 0; j < channelCount; ++j) {
                inData[i * channelCount + j] = (j < 2) ? channelValue : 0;
            }
        }

        ASSERT_EQ(NO_ERROR, effect_process(handle, &inBuffer, &outBuffer));

        ASSERT_EQ(NO_ERROR, (*(effect_interface_s **)handle)->command(
                handle, VISUALIZER_CMD_CAPTURE, 0 /* cmdSize */, nullptr /* pCmdData */,
                &replySize, replyData.data()));

        // Normalized to max
        constexpr int kUnsignedByteMax = 0xff;
        EXPECT_EQ(kUnsignedByteMax, replyData[0]);
        const bool capture_set_stereo = std::all_of(
                replyData.begin(), replyData.end(),
                [](uint8_t datum){ return datum == kUnsignedByteMax; });
        EXPECT_TRUE(capture_set_stereo);


        const uint32_t captureMode = VISUALIZER_SCALING_MODE_AS_PLAYED;
        EXPECT_EQ(NO_ERROR,
                effect_set_param(handle, VISUALIZER_PARAM_SCALING_MODE, captureMode));

        ASSERT_EQ(NO_ERROR, effect_process(handle, &inBuffer, &outBuffer));

        ASSERT_EQ(NO_ERROR, (*(effect_interface_s **)handle)->command(
                handle, VISUALIZER_CMD_CAPTURE, 0 /* cmdSize */, nullptr /* pCmdData */,
                &replySize, replyData.data()));

        const float fscale = channelCount == 1 ? 1.f : 2.f / channelCount;

        // Implementation detail: clamp8_from_float() rounds 0.5 lsb is away from 0.
        const auto round = [](float value) {
            return roundf(fmaxf(fminf(value * 128.f + 128.f, 255.f), 0.f));
        };
        const float expectedValue = round(channelValue * fscale);
        EXPECT_EQ(expectedValue, replyData[0]);

        ASSERT_EQ(NO_ERROR, AUDIO_EFFECT_LIBRARY_INFO_SYM.release_effect(handle));
    }

    void testCaptureSize(audio_channel_mask_t channelMask) {
        effect_handle_t handle;
        ASSERT_EQ(0, AUDIO_EFFECT_LIBRARY_INFO_SYM.create_effect(
                           &sVisualizerUuid, 0 /* sessionId */, 0 /* ioId */, &handle));

        constexpr uint32_t sampleRate = 48000;
        ASSERT_EQ(NO_ERROR,
                effect_set_config(handle, sampleRate, channelMask, true /* accumulate */));
        ASSERT_EQ(NO_ERROR, effect_enable(handle));

        // VISUALIZER_CAPTURE_SIZE_MAX 1024
        // VISUALIZER_CAPTURE_SIZE_MIN 128

        for (uint32_t captureSize : {128, 256, 512, 1024}) {
            EXPECT_EQ(NO_ERROR,
                    effect_set_param(handle, VISUALIZER_PARAM_CAPTURE_SIZE, captureSize));
            uint32_t returnedCaptureSize = 0;
            EXPECT_EQ(NO_ERROR,
                    effect_get_param(handle, VISUALIZER_PARAM_CAPTURE_SIZE, returnedCaptureSize));
            EXPECT_EQ(captureSize, returnedCaptureSize);
        }

        ASSERT_EQ(NO_ERROR, AUDIO_EFFECT_LIBRARY_INFO_SYM.release_effect(handle));
    }

private:
    static constexpr effect_uuid_t sVisualizerUuid = {
            0xd069d9e0, 0x8329, 0x11df, 0x9168, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}};
};

TEST_P(EffectVisualizerParamTest, CaptureSize) {
    testCaptureSize(kChannelMasks[std::get<CHANNEL_MASK_POSITION>(GetParam())]);
}

TEST_P(EffectVisualizerParamTest, Capture) {
    testCapture(kChannelMasks[std::get<CHANNEL_MASK_POSITION>(GetParam())]);
}

INSTANTIATE_TEST_SUITE_P(
        EffectVisualizerTestAll, EffectVisualizerParamTest,
        ::testing::Combine(::testing::Range(0, (int)std::size(kChannelMasks))),
        [](const testing::TestParamInfo<EffectVisualizerParamTest::ParamType>& info) {
            const int index = std::get<CHANNEL_MASK_POSITION>(info.param);
            const audio_channel_mask_t channelMask = kChannelMasks[index];
            const std::string name = std::string(audio_channel_out_mask_to_string(channelMask));
            return name;
        });
