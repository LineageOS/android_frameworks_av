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
    AUDIO_CHANNEL_OUT_QUAD, // AUDIO_CHANNEL_OUT_QUAD_BACK
    AUDIO_CHANNEL_OUT_QUAD_SIDE,
    AUDIO_CHANNEL_OUT_SURROUND,
    AUDIO_CHANNEL_OUT_2POINT1POINT2,
    AUDIO_CHANNEL_OUT_3POINT0POINT2,
    AUDIO_CHANNEL_OUT_PENTA,
    AUDIO_CHANNEL_OUT_3POINT1POINT2,
    AUDIO_CHANNEL_OUT_5POINT1, // AUDIO_CHANNEL_OUT_5POINT1_BACK
    AUDIO_CHANNEL_OUT_5POINT1_SIDE,
    AUDIO_CHANNEL_OUT_6POINT1,
    AUDIO_CHANNEL_OUT_5POINT1POINT2,
    AUDIO_CHANNEL_OUT_7POINT1,
    AUDIO_CHANNEL_OUT_5POINT1POINT4,
    AUDIO_CHANNEL_OUT_7POINT1POINT2,
    AUDIO_CHANNEL_OUT_7POINT1POINT4,
    AUDIO_CHANNEL_OUT_13POINT_360RA,
    AUDIO_CHANNEL_OUT_22POINT2,
    audio_channel_mask_t(AUDIO_CHANNEL_OUT_22POINT2
            | AUDIO_CHANNEL_OUT_FRONT_WIDE_LEFT | AUDIO_CHANNEL_OUT_FRONT_WIDE_RIGHT),
};

constexpr float COEF_25 = 0.2508909536f;
constexpr float COEF_35 = 0.3543928915f;
constexpr float COEF_36 = 0.3552343859f;
constexpr float COEF_61 = 0.6057043428f;

constexpr inline float kScaleFromChannelIdxLeft[] = {
    1.f,       // AUDIO_CHANNEL_OUT_FRONT_LEFT            = 0x1u,
    0.f,       // AUDIO_CHANNEL_OUT_FRONT_RIGHT           = 0x2u,
    M_SQRT1_2, // AUDIO_CHANNEL_OUT_FRONT_CENTER          = 0x4u,
    0.5f,      // AUDIO_CHANNEL_OUT_LOW_FREQUENCY         = 0x8u,
    M_SQRT1_2, // AUDIO_CHANNEL_OUT_BACK_LEFT             = 0x10u,
    0.f,       // AUDIO_CHANNEL_OUT_BACK_RIGHT            = 0x20u,
    COEF_61,   // AUDIO_CHANNEL_OUT_FRONT_LEFT_OF_CENTER  = 0x40u,
    COEF_25,   // AUDIO_CHANNEL_OUT_FRONT_RIGHT_OF_CENTER = 0x80u,
    0.5f,      // AUDIO_CHANNEL_OUT_BACK_CENTER           = 0x100u,
    M_SQRT1_2, // AUDIO_CHANNEL_OUT_SIDE_LEFT             = 0x200u,
    0.f,       // AUDIO_CHANNEL_OUT_SIDE_RIGHT            = 0x400u,
    COEF_36,   // AUDIO_CHANNEL_OUT_TOP_CENTER            = 0x800u,
    1.f,       // AUDIO_CHANNEL_OUT_TOP_FRONT_LEFT        = 0x1000u,
    M_SQRT1_2, // AUDIO_CHANNEL_OUT_TOP_FRONT_CENTER      = 0x2000u,
    0.f,       // AUDIO_CHANNEL_OUT_TOP_FRONT_RIGHT       = 0x4000u,
    M_SQRT1_2, // AUDIO_CHANNEL_OUT_TOP_BACK_LEFT         = 0x8000u,
    COEF_35,   // AUDIO_CHANNEL_OUT_TOP_BACK_CENTER       = 0x10000u,
    0.f,       // AUDIO_CHANNEL_OUT_TOP_BACK_RIGHT        = 0x20000u,
    COEF_61,   // AUDIO_CHANNEL_OUT_TOP_SIDE_LEFT         = 0x40000u,
    0.f,       // AUDIO_CHANNEL_OUT_TOP_SIDE_RIGHT        = 0x80000u,
    1.f,       // AUDIO_CHANNEL_OUT_BOTTOM_FRONT_LEFT     = 0x100000u,
    M_SQRT1_2, // AUDIO_CHANNEL_OUT_BOTTOM_FRONT_CENTER   = 0x200000u,
    0.f, // AUDIO_CHANNEL_OUT_BOTTOM_FRONT_RIGHT    = 0x400000u,
    0.f, // AUDIO_CHANNEL_OUT_LOW_FREQUENCY_2       = 0x800000u,
    M_SQRT1_2, // AUDIO_CHANNEL_OUT_FRONT_WIDE_LEFT       = 0x1000000u,
    0.f,       // AUDIO_CHANNEL_OUT_FRONT_WIDE_RIGHT      = 0x2000000u,
};

constexpr inline float kScaleFromChannelIdxRight[] = {
    0.f,       // AUDIO_CHANNEL_OUT_FRONT_LEFT            = 0x1u,
    1.f,       // AUDIO_CHANNEL_OUT_FRONT_RIGHT           = 0x2u,
    M_SQRT1_2, // AUDIO_CHANNEL_OUT_FRONT_CENTER          = 0x4u,
    0.5f,      // AUDIO_CHANNEL_OUT_LOW_FREQUENCY         = 0x8u,
    0.f,       // AUDIO_CHANNEL_OUT_BACK_LEFT             = 0x10u,
    M_SQRT1_2, // AUDIO_CHANNEL_OUT_BACK_RIGHT            = 0x20u,
    COEF_25,   // AUDIO_CHANNEL_OUT_FRONT_LEFT_OF_CENTER  = 0x40u,
    COEF_61,   // AUDIO_CHANNEL_OUT_FRONT_RIGHT_OF_CENTER = 0x80u,
    0.5f,      // AUDIO_CHANNEL_OUT_BACK_CENTER           = 0x100u,
    0.f,       // AUDIO_CHANNEL_OUT_SIDE_LEFT             = 0x200u,
    M_SQRT1_2, // AUDIO_CHANNEL_OUT_SIDE_RIGHT            = 0x400u,
    COEF_36,   // AUDIO_CHANNEL_OUT_TOP_CENTER            = 0x800u,
    0.f,       // AUDIO_CHANNEL_OUT_TOP_FRONT_LEFT        = 0x1000u,
    M_SQRT1_2, // AUDIO_CHANNEL_OUT_TOP_FRONT_CENTER      = 0x2000u,
    1.f,       // AUDIO_CHANNEL_OUT_TOP_FRONT_RIGHT       = 0x4000u,
    0.f,       // AUDIO_CHANNEL_OUT_TOP_BACK_LEFT         = 0x8000u,
    COEF_35,   // AUDIO_CHANNEL_OUT_TOP_BACK_CENTER       = 0x10000u,
    M_SQRT1_2, // AUDIO_CHANNEL_OUT_TOP_BACK_RIGHT        = 0x20000u,
    0.f,       // AUDIO_CHANNEL_OUT_TOP_SIDE_LEFT         = 0x40000u,
    COEF_61,   // AUDIO_CHANNEL_OUT_TOP_SIDE_RIGHT        = 0x80000u,
    0.f,       // AUDIO_CHANNEL_OUT_BOTTOM_FRONT_LEFT     = 0x100000u,
    M_SQRT1_2, // AUDIO_CHANNEL_OUT_BOTTOM_FRONT_CENTER   = 0x200000u,
    1.f,       // AUDIO_CHANNEL_OUT_BOTTOM_FRONT_RIGHT    = 0x400000u,
    M_SQRT1_2, // AUDIO_CHANNEL_OUT_LOW_FREQUENCY_2       = 0x800000u,
    0.f,       // AUDIO_CHANNEL_OUT_FRONT_WIDE_LEFT       = 0x1000000u,
    M_SQRT1_2, // AUDIO_CHANNEL_OUT_FRONT_WIDE_RIGHT      = 0x2000000u,
};

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

        size_t frames = 100; // set to an even number (2, 4, 6 ... ) stream alternates +1, -1.
        constexpr unsigned outChannels = 2;
        unsigned inChannels = audio_channel_count_from_out_mask(channelMask);
        std::vector<float> input(frames * inChannels);
        std::vector<float> output(frames * outChannels);

        double savedPower[32][2]{};
        for (unsigned i = 0, channel = channelMask; channel != 0; ++i) {
            const int index = __builtin_ctz(channel);
            ASSERT_LT(index, FCC_26);
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
            double power[2] = { stats[0].getPopVariance(), stats[1].getPopVariance() };

            // Check symmetric power for pair channels on exchange of left/right position.
            // to do this, we save previous power measurements.
            if (pairIndex >= 0 && pairIndex < index) {
                EXPECT_NEAR_EPSILON(power[0], savedPower[pairIndex][1]);
                EXPECT_NEAR_EPSILON(power[1], savedPower[pairIndex][0]);
            }
            savedPower[index][0] = power[0];
            savedPower[index][1] = power[1];

            constexpr float POWER_TOLERANCE = 0.001;
            const float expectedPower =
                    kScaleFromChannelIdxLeft[index] * kScaleFromChannelIdxLeft[index]
                    + kScaleFromChannelIdxRight[index] * kScaleFromChannelIdxRight[index];
            EXPECT_NEAR(expectedPower, power[0] + power[1], POWER_TOLERANCE);
            switch (side) {
            case AUDIO_GEOMETRY_SIDE_LEFT:
                if (channelBit == AUDIO_CHANNEL_OUT_FRONT_LEFT_OF_CENTER) {
                    break;
                }
                EXPECT_EQ(0.f, power[1]);
                break;
            case AUDIO_GEOMETRY_SIDE_RIGHT:
                if (channelBit == AUDIO_CHANNEL_OUT_FRONT_RIGHT_OF_CENTER) {
                    break;
                }
                EXPECT_EQ(0.f, power[0]);
                break;
            case AUDIO_GEOMETRY_SIDE_CENTER:
                if (channelBit == AUDIO_CHANNEL_OUT_LOW_FREQUENCY) {
                    if (channelMask & AUDIO_CHANNEL_OUT_LOW_FREQUENCY_2) {
                        EXPECT_EQ(0.f, power[1]);
                        break;
                    } else {
                        EXPECT_NEAR_EPSILON(power[0], power[1]); // always true
                        EXPECT_NEAR(expectedPower, power[0] + power[1], POWER_TOLERANCE);
                        break;
                    }
                } else if (channelBit == AUDIO_CHANNEL_OUT_LOW_FREQUENCY_2) {
                    EXPECT_EQ(0.f, power[0]);
                    EXPECT_NEAR(expectedPower, power[1], POWER_TOLERANCE);
                    break;
                }
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
        ASSERT_EQ(0, reply);
        err = (downmixApi->command)(
                handle_, EFFECT_CMD_ENABLE,
                0, nullptr, &replySize, &reply);
        ASSERT_EQ(0, err);

        process(input, output, frames);
        err = AUDIO_EFFECT_LIBRARY_INFO_SYM.release_effect(handle_);
        ASSERT_EQ(0, err);
    }

    // This test assumes the channel mask is invalid.
    void testInvalidChannelMask(audio_channel_mask_t invalidChannelMask) {
        reconfig(48000 /* sampleRate */, invalidChannelMask);
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
        ASSERT_NE(0, reply);  // error has occurred.
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

TEST(DownmixTestSimple, invalidChannelMask) {
    // Fill in a dummy test method to use DownmixTest outside of a parameterized test.
    class DownmixTestComplete : public DownmixTest {
        void TestBody() override {}
    } downmixtest;

    constexpr auto INVALID_CHANNEL_MASK = audio_channel_mask_t(1 << 31);
    downmixtest.testInvalidChannelMask(INVALID_CHANNEL_MASK);
}

TEST_P(DownmixTest, basic) {
    testBalance(kSampleRates[std::get<0>(GetParam())],
            kChannelPositionMasks[std::get<1>(GetParam())]);
}

INSTANTIATE_TEST_SUITE_P(
        DownmixTestAll, DownmixTest,
        ::testing::Combine(
                ::testing::Range(0, (int)std::size(kSampleRates)),
                ::testing::Range(0, (int)std::size(kChannelPositionMasks))
                ),
        [](const testing::TestParamInfo<DownmixTest::ParamType>& info) {
            const int index = std::get<1>(info.param);
            const audio_channel_mask_t channelMask = kChannelPositionMasks[index];
            const std::string name = std::string(audio_channel_out_mask_to_string(channelMask))
                + "_" + std::to_string(std::get<0>(info.param)) + "_" + std::to_string(index);
            return name;
        });
