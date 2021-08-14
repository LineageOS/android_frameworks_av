/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include <vector>

#include "EffectDownmix.h"

#include <audio_utils/channels.h>
#include <audio_utils/primitives.h>
#include <audio_utils/Statistics.h>
#include <gtest/gtest.h>
#include <log/log.h>

extern audio_effect_library_t AUDIO_EFFECT_LIBRARY_INFO_SYM;
static constexpr audio_channel_mask_t kChannelPositionMasks[] = {
    AUDIO_CHANNEL_OUT_FRONT_LEFT, // Legacy: the downmix effect treats MONO as FRONT_LEFT only.
                                  // The AudioMixer interprets MONO as a special case requiring
                                  // channel replication, bypassing the downmix effect.
    AUDIO_CHANNEL_OUT_FRONT_CENTER,
    AUDIO_CHANNEL_OUT_STEREO,
    AUDIO_CHANNEL_OUT_2POINT1,
    AUDIO_CHANNEL_OUT_2POINT0POINT2,
    AUDIO_CHANNEL_OUT_QUAD,
    AUDIO_CHANNEL_OUT_QUAD_BACK,
    AUDIO_CHANNEL_OUT_QUAD_SIDE,
    AUDIO_CHANNEL_OUT_SURROUND,
    AUDIO_CHANNEL_OUT_2POINT1POINT2,
    AUDIO_CHANNEL_OUT_3POINT0POINT2,
    AUDIO_CHANNEL_OUT_PENTA,
    AUDIO_CHANNEL_OUT_3POINT1POINT2,
    AUDIO_CHANNEL_OUT_5POINT1,
    AUDIO_CHANNEL_OUT_5POINT1_BACK,
    AUDIO_CHANNEL_OUT_5POINT1_SIDE,
    AUDIO_CHANNEL_OUT_6POINT1,
    AUDIO_CHANNEL_OUT_5POINT1POINT2,
    AUDIO_CHANNEL_OUT_7POINT1,
    AUDIO_CHANNEL_OUT_5POINT1POINT4,
    AUDIO_CHANNEL_OUT_7POINT1POINT2,
    AUDIO_CHANNEL_OUT_7POINT1POINT4,
    AUDIO_CHANNEL_OUT_13POINT_360RA,
    AUDIO_CHANNEL_OUT_22POINT2,
};

static constexpr audio_channel_mask_t kConsideredChannels =
    (audio_channel_mask_t)(AUDIO_CHANNEL_OUT_7POINT1 | AUDIO_CHANNEL_OUT_BACK_CENTER);

// Downmix doesn't change with sample rate
static constexpr size_t kSampleRates[] = {
    48000,
};

// Our near expectation is 16x the bit that doesn't fit the mantissa.
// this works so long as we add values close in exponent with each other
// realizing that errors accumulate as the sqrt of N (random walk, lln, etc).
#define EXPECT_NEAR_EPSILON(e, v) EXPECT_NEAR((e), (v), \
        abs((e) * std::numeric_limits<std::decay_t<decltype(e)>>::epsilon() * 8))

template<typename T>
static auto channelStatistics(const std::vector<T>& input, size_t channels) {
    std::vector<android::audio_utils::Statistics<T>> result(channels);
    const size_t frames = input.size() / channels;
    if (frames > 0) {
        const float *fptr = input.data();
        for (size_t i = 0; i < frames; ++i) {
            for (size_t j = 0; j < channels; ++j) {
                result[j].add(*fptr++);
            }
        }
    }
    return result;
}

using DownmixParam = std::tuple<int /* sample rate */,  int /* channel mask */>;
class DownmixTest : public ::testing::TestWithParam<DownmixParam> {
public:
    static constexpr effect_uuid_t downmix_uuid_ = {
        0x93f04452, 0xe4fe, 0x41cc, 0x91f9, {0xe4, 0x75, 0xb6, 0xd1, 0xd6, 0x9f}};
    static constexpr size_t FRAME_LENGTH = 256;

    void testBalance(int sampleRate, audio_channel_mask_t channelMask) {
        using namespace ::android::audio_utils::channels;

        size_t frames = 100;
        unsigned outChannels = 2;
        unsigned inChannels = audio_channel_count_from_out_mask(channelMask);
        std::vector<float> input(frames * inChannels);
        std::vector<float> output(frames * outChannels);

        double savedPower[32][2]{};
        for (unsigned i = 0, channel = channelMask; channel != 0; ++i) {
            const int index = __builtin_ctz(channel);
            ASSERT_LT(index, FCC_24);
            const int pairIndex = pairIdxFromChannelIdx(index);
            const AUDIO_GEOMETRY_SIDE side = sideFromChannelIdx(index);
            const int channelBit = 1 << index;
            channel &= ~channelBit;

            // Generate a +1, -1 alternating stream in one channel, which has variance 1.
            auto indata = input.data();
            for (unsigned j = 0; j < frames; ++j) {
                for (unsigned k = 0; k < inChannels; ++k) {
                    *indata++ = (k == i) ? (j & 1 ? -1 : 1) : 0;
                }
            }
            run(sampleRate, channelMask, input, output, frames);

            auto stats = channelStatistics(output, 2 /* channels */);
            // printf("power: %s %s\n", stats[0].toString().c_str(), stats[1].toString().c_str());
            double power[2] = { stats[0].getVariance(), stats[1].getVariance() };

            // Check symmetric power for pair channels on exchange of left/right position.
            // to do this, we save previous power measurements.
            if (pairIndex >= 0 && pairIndex < index) {
                EXPECT_NEAR_EPSILON(power[0], savedPower[pairIndex][1]);
                EXPECT_NEAR_EPSILON(power[1], savedPower[pairIndex][0]);
            }
            savedPower[index][0] = power[0];
            savedPower[index][1] = power[1];

            // Confirm exactly the mix amount prescribed by the existing downmix effect.
            // For future changes to the downmix effect, the nearness needs to be relaxed
            // to compare behavior S or earlier.
            if ((channelBit & kConsideredChannels) == 0) {
                // for channels not considered, expect 0 power for legacy downmix
                EXPECT_EQ(0.f, power[0]);
                EXPECT_EQ(0.f, power[1]);
                continue;
            }
            constexpr float POWER_TOLERANCE = 0.01;  // for variance sum error.
            switch (side) {
            case AUDIO_GEOMETRY_SIDE_LEFT:
                EXPECT_NEAR(0.25f, power[0], POWER_TOLERANCE);
                EXPECT_EQ(0.f, power[1]);
                break;
            case AUDIO_GEOMETRY_SIDE_RIGHT:
                EXPECT_EQ(0.f, power[0]);
                EXPECT_NEAR(0.25f, power[1], POWER_TOLERANCE);
                break;
            case AUDIO_GEOMETRY_SIDE_CENTER:
                EXPECT_NEAR(0.125f, power[0], POWER_TOLERANCE);
                EXPECT_NEAR(0.125f, power[1], POWER_TOLERANCE);
                EXPECT_NEAR_EPSILON(power[0], power[1]);
                break;
            }
        }
    }

    void run(int sampleRate, audio_channel_mask_t channelMask,
            std::vector<float>& input, std::vector<float>& output, size_t frames) {
        reconfig(sampleRate, channelMask);

        ASSERT_EQ(frames * inputChannelCount_, input.size());
        ASSERT_EQ(frames * outputChannelCount_, output.size());

        const int32_t sessionId = 0;
        const int32_t ioId = 0;
        int32_t err = AUDIO_EFFECT_LIBRARY_INFO_SYM.create_effect(
                &downmix_uuid_, sessionId, ioId,  &handle_);
        ASSERT_EQ(0, err);

        const struct effect_interface_s * const downmixApi = *handle_;
        int32_t reply = 0;
        uint32_t replySize = (uint32_t)sizeof(reply);
        err = (downmixApi->command)(
                handle_, EFFECT_CMD_SET_CONFIG,
                sizeof(effect_config_t), &config_, &replySize, &reply);
        ASSERT_EQ(0, err);
        err = (downmixApi->command)(
                handle_, EFFECT_CMD_ENABLE,
                0, nullptr, &replySize, &reply);
        ASSERT_EQ(0, err);

        process(input, output, frames);
        err = AUDIO_EFFECT_LIBRARY_INFO_SYM.release_effect(handle_);
        ASSERT_EQ(0, err);
    }

private:
    void reconfig(int sampleRate, audio_channel_mask_t channelMask) {
        config_.inputCfg.accessMode = EFFECT_BUFFER_ACCESS_READ;
        config_.inputCfg.format = AUDIO_FORMAT_PCM_FLOAT;
        config_.inputCfg.bufferProvider.getBuffer = nullptr;
        config_.inputCfg.bufferProvider.releaseBuffer = nullptr;
        config_.inputCfg.bufferProvider.cookie = nullptr;
        config_.inputCfg.mask = EFFECT_CONFIG_ALL;

        config_.outputCfg.accessMode = EFFECT_BUFFER_ACCESS_WRITE;
        config_.outputCfg.format = AUDIO_FORMAT_PCM_FLOAT;
        config_.outputCfg.bufferProvider.getBuffer = nullptr;
        config_.outputCfg.bufferProvider.releaseBuffer = nullptr;
        config_.outputCfg.bufferProvider.cookie = nullptr;
        config_.outputCfg.mask = EFFECT_CONFIG_ALL;

        config_.inputCfg.samplingRate = sampleRate;
        config_.inputCfg.channels = channelMask;
        inputChannelCount_ = audio_channel_count_from_out_mask(config_.inputCfg.channels);

        config_.outputCfg.samplingRate = sampleRate;
        config_.outputCfg.channels = AUDIO_CHANNEL_OUT_STEREO; // output always stereo
        outputChannelCount_ = audio_channel_count_from_out_mask(config_.outputCfg.channels);
    }

    void process(std::vector<float> &input, std::vector<float> &output, size_t frames) const {
        const struct effect_interface_s * const downmixApi = *handle_;

        for (size_t pos = 0; pos < frames;) {
            const size_t transfer = std::min(frames - pos, FRAME_LENGTH);
            audio_buffer_t inbuffer{.frameCount = transfer,
                .f32 = input.data() + pos * inputChannelCount_};
            audio_buffer_t outbuffer{.frameCount = transfer,
                .f32 = output.data() + pos * outputChannelCount_};
            const int32_t err = (downmixApi->process)(handle_, &inbuffer, &outbuffer);
            ASSERT_EQ(0, err);
            pos += transfer;
        }
    }

    effect_handle_t handle_{};
    effect_config_t config_{};
    int outputChannelCount_{};
    int inputChannelCount_{};
};

TEST_P(DownmixTest, basic) {
    testBalance(kSampleRates[std::get<0>(GetParam())],
            kChannelPositionMasks[std::get<1>(GetParam())]);
}

INSTANTIATE_TEST_SUITE_P(
        DownmixTestAll, DownmixTest,
        ::testing::Combine(
                ::testing::Range(0, (int)std::size(kSampleRates)),
                ::testing::Range(0, (int)std::size(kChannelPositionMasks))
                ));

int main(int argc, /* const */ char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int status = RUN_ALL_TESTS();
    return status;
}
