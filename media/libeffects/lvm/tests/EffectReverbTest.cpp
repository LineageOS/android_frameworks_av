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

#include <audio_effects/effect_presetreverb.h>
#include <VectorArithmetic.h>

#include "EffectTestHelper.h"
using namespace android;

constexpr effect_uuid_t kEffectUuids[] = {
        // NXP SW insert environmental reverb
        {0xc7a511a0, 0xa3bb, 0x11df, 0x860e, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}},
        // NXP SW insert preset reverb
        {0x172cdf00, 0xa3bc, 0x11df, 0xa72f, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}},
        // NXP SW auxiliary environmental reverb
        {0x4a387fc0, 0x8ab3, 0x11df, 0x8bad, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}},
        // NXP SW auxiliary preset reverb
        {0xf29a1400, 0xa3bb, 0x11df, 0x8ddc, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}},
};

constexpr size_t kNumEffectUuids = std::size(kEffectUuids);

static constexpr audio_channel_mask_t kChMasks[] = {
        AUDIO_CHANNEL_OUT_MONO,          AUDIO_CHANNEL_OUT_STEREO,
        AUDIO_CHANNEL_OUT_2POINT1,       AUDIO_CHANNEL_OUT_5POINT1,
        AUDIO_CHANNEL_OUT_7POINT1POINT4, AUDIO_CHANNEL_INDEX_MASK_23,
        AUDIO_CHANNEL_OUT_22POINT2,
};

static constexpr size_t kNumChMasks = std::size(kChMasks);

static constexpr size_t kSampleRates[] = {8000, 11025, 44100, 48000, 192000};

static constexpr size_t kNumSampleRates = std::size(kSampleRates);

static constexpr size_t kFrameCounts[] = {4, 512};

static constexpr size_t kNumFrameCounts = std::size(kFrameCounts);

static constexpr size_t kLoopCounts[] = {1, 4};

static constexpr size_t kNumLoopCounts = std::size(kLoopCounts);

static bool isAuxMode(const effect_uuid_t* uuid) {
    // Update this, if the order of effects in kEffectUuids is updated
    return (uuid == &kEffectUuids[2] || uuid == &kEffectUuids[3]);
}

constexpr int kPresets[] = {
        REVERB_PRESET_NONE,      REVERB_PRESET_SMALLROOM,  REVERB_PRESET_MEDIUMROOM,
        REVERB_PRESET_LARGEROOM, REVERB_PRESET_MEDIUMHALL, REVERB_PRESET_LARGEHALL,
        REVERB_PRESET_PLATE,
};

constexpr size_t kNumPresets = std::size(kPresets);

typedef std::tuple<int, int, int, int, int, int> SingleEffectTestParam;
class SingleEffectTest : public ::testing::TestWithParam<SingleEffectTestParam> {
  public:
    SingleEffectTest()
        : mSampleRate(kSampleRates[std::get<1>(GetParam())]),
          mFrameCount(kFrameCounts[std::get<2>(GetParam())]),
          mLoopCount(kLoopCounts[std::get<3>(GetParam())]),
          mTotalFrameCount(mFrameCount * mLoopCount),
          mUuid(&kEffectUuids[std::get<4>(GetParam())]),
          mInChMask(isAuxMode(mUuid) ? AUDIO_CHANNEL_OUT_MONO
                                     : kChMasks[std::get<0>(GetParam())]),
          mInChannelCount(audio_channel_count_from_out_mask(mInChMask)),
          mOutChMask(kChMasks[std::get<0>(GetParam())]),
          mOutChannelCount(audio_channel_count_from_out_mask(mOutChMask)),
          mPreset(kPresets[std::get<5>(GetParam())]) {}

    const size_t mSampleRate;
    const size_t mFrameCount;
    const size_t mLoopCount;
    const size_t mTotalFrameCount;
    const effect_uuid_t* mUuid;
    const size_t mInChMask;
    const size_t mInChannelCount;
    const size_t mOutChMask;
    const size_t mOutChannelCount;
    const size_t mPreset;
};

// Tests applying a single effect
TEST_P(SingleEffectTest, SimpleProcess) {
    SCOPED_TRACE(testing::Message() << "outChMask: " << mOutChMask << " sampleRate: " << mSampleRate
                                    << " frameCount: " << mFrameCount
                                    << " loopCount: " << mLoopCount << " preset: " << mPreset);

    EffectTestHelper effect(mUuid, mInChMask, mOutChMask, mSampleRate, mFrameCount, mLoopCount);

    ASSERT_NO_FATAL_FAILURE(effect.createEffect());
    ASSERT_NO_FATAL_FAILURE(effect.setConfig());
    ASSERT_NO_FATAL_FAILURE(effect.setParam(REVERB_PARAM_PRESET, mPreset));

    // Initialize input buffer with deterministic pseudo-random values
    std::vector<float> input(mTotalFrameCount * mInChannelCount);
    std::vector<float> output(mTotalFrameCount * mOutChannelCount);
    std::minstd_rand gen(mOutChMask);
    std::uniform_real_distribution<> dis(-1.0f, 1.0f);
    for (auto& in : input) {
        in = dis(gen);
    }
    ASSERT_NO_FATAL_FAILURE(effect.process(input.data(), output.data()));
    ASSERT_NO_FATAL_FAILURE(effect.releaseEffect());
}

INSTANTIATE_TEST_SUITE_P(
        EffectReverbTestAll, SingleEffectTest,
        ::testing::Combine(::testing::Range(0, (int)kNumChMasks),
                           ::testing::Range(0, (int)kNumSampleRates),
                           ::testing::Range(0, (int)kNumFrameCounts),
                           ::testing::Range(0, (int)kNumLoopCounts),
                           ::testing::Range(0, (int)kNumEffectUuids),
                           ::testing::Range(0, (int)kNumPresets)));

typedef std::tuple<int, int, int, int, int> SingleEffectComparisonTestParam;
class SingleEffectComparisonTest
    : public ::testing::TestWithParam<SingleEffectComparisonTestParam> {
  public:
    SingleEffectComparisonTest()
        : mSampleRate(kSampleRates[std::get<0>(GetParam())]),
          mFrameCount(kFrameCounts[std::get<1>(GetParam())]),
          mLoopCount(kLoopCounts[std::get<2>(GetParam())]),
          mTotalFrameCount(mFrameCount * mLoopCount),
          mUuid(&kEffectUuids[std::get<3>(GetParam())]),
          mPreset(kPresets[std::get<4>(GetParam())]) {}

    const size_t mSampleRate;
    const size_t mFrameCount;
    const size_t mLoopCount;
    const size_t mTotalFrameCount;
    const effect_uuid_t* mUuid;
    const size_t mPreset;
};

// Compares first two channels in multi-channel output to stereo output when same effect is applied
TEST_P(SingleEffectComparisonTest, SimpleProcess) {
    SCOPED_TRACE(testing::Message()
                 << " sampleRate: " << mSampleRate << " frameCount: " << mFrameCount
                 << " loopCount: " << mLoopCount << " preset: " << mPreset);

    // Initialize mono input buffer with deterministic pseudo-random values
    std::vector<float> monoInput(mTotalFrameCount);

    std::minstd_rand gen(mSampleRate);
    std::uniform_real_distribution<> dis(-1.0f, 1.0f);
    for (auto& in : monoInput) {
        in = dis(gen);
    }

    // Generate stereo by repeating mono channel data
    std::vector<float> stereoInput(mTotalFrameCount * FCC_2);
    adjust_channels(monoInput.data(), FCC_1, stereoInput.data(), FCC_2, sizeof(float),
                    mTotalFrameCount * sizeof(float) * FCC_1);

    // Apply effect on stereo channels
    EffectTestHelper stereoEffect(
            mUuid, isAuxMode(mUuid) ? AUDIO_CHANNEL_OUT_MONO : AUDIO_CHANNEL_OUT_STEREO,
            AUDIO_CHANNEL_OUT_STEREO, mSampleRate, mFrameCount, mLoopCount);

    ASSERT_NO_FATAL_FAILURE(stereoEffect.createEffect());
    ASSERT_NO_FATAL_FAILURE(stereoEffect.setConfig());
    ASSERT_NO_FATAL_FAILURE(stereoEffect.setParam(REVERB_PARAM_PRESET, mPreset));

    std::vector<float> stereoOutput(mTotalFrameCount * FCC_2);
    ASSERT_NO_FATAL_FAILURE(stereoEffect.process(
            (isAuxMode(mUuid) ? monoInput.data() : stereoInput.data()), stereoOutput.data()));
    ASSERT_NO_FATAL_FAILURE(stereoEffect.releaseEffect());

    // Average of both channels data is stored for mono comparison
    std::vector<float> monoOutput(mTotalFrameCount);
    From2iToMono_Float((const float*)stereoOutput.data(), monoOutput.data(), mTotalFrameCount);

    // Convert stereo float data to stereo int16_t to be used as reference
    std::vector<int16_t> stereoRefI16(mTotalFrameCount * FCC_2);
    memcpy_to_i16_from_float(stereoRefI16.data(), stereoOutput.data(), mTotalFrameCount * FCC_2);

    // mono int16_t to be used as refernece for mono comparison
    std::vector<int16_t> monoRefI16(mTotalFrameCount);
    memcpy_to_i16_from_float(monoRefI16.data(), monoOutput.data(), mTotalFrameCount);

    for (size_t outChMask : kChMasks) {
        size_t outChannelCount = audio_channel_count_from_out_mask(outChMask);
        size_t inChMask = isAuxMode(mUuid) ? AUDIO_CHANNEL_OUT_MONO : outChMask;

        EffectTestHelper testEffect(mUuid, inChMask, outChMask, mSampleRate, mFrameCount,
                                    mLoopCount);

        ASSERT_NO_FATAL_FAILURE(testEffect.createEffect());
        ASSERT_NO_FATAL_FAILURE(testEffect.setConfig());
        ASSERT_NO_FATAL_FAILURE(testEffect.setParam(REVERB_PARAM_PRESET, mPreset));

        std::vector<float> testInput(mTotalFrameCount * outChannelCount);

        // Repeat mono channel data to all the channels
        // adjust_channels() zero fills channels > 2, hence can't be used here
        for (size_t i = 0; i < mTotalFrameCount; ++i) {
            auto* fp = &testInput[i * outChannelCount];
            std::fill(fp, fp + outChannelCount, monoInput[i]);
        }

        std::vector<float> testOutput(mTotalFrameCount * outChannelCount);
        ASSERT_NO_FATAL_FAILURE(testEffect.process(
                (isAuxMode(mUuid) ? monoInput.data() : testInput.data()), testOutput.data()));
        ASSERT_NO_FATAL_FAILURE(testEffect.releaseEffect());

        if (outChannelCount == FCC_1) {
            // Convert the test data to int16_t
            std::vector<int16_t> monoTestI16(mTotalFrameCount);
            memcpy_to_i16_from_float(monoTestI16.data(), testOutput.data(), mTotalFrameCount);

            ASSERT_EQ(0, memcmp(monoRefI16.data(), monoTestI16.data(), mTotalFrameCount * FCC_2))
                    << "Mono channel do not match with reference output \n";
        } else {
            // Extract first two channels
            std::vector<float> stereoTestOutput(mTotalFrameCount * FCC_2);
            adjust_channels(testOutput.data(), outChannelCount, stereoTestOutput.data(), FCC_2,
                            sizeof(float), mTotalFrameCount * sizeof(float) * outChannelCount);

            // Convert the test data to int16_t
            std::vector<int16_t> stereoTestI16(mTotalFrameCount * FCC_2);
            memcpy_to_i16_from_float(stereoTestI16.data(), stereoTestOutput.data(),
                                     mTotalFrameCount * FCC_2);

            ASSERT_EQ(0,
                      memcmp(stereoRefI16.data(), stereoTestI16.data(), mTotalFrameCount * FCC_2))
                    << "First two channels do not match with stereo output \n";
        }
    }
}

INSTANTIATE_TEST_SUITE_P(
        EffectReverbTestAll, SingleEffectComparisonTest,
        ::testing::Combine(::testing::Range(0, (int)kNumSampleRates),
                           ::testing::Range(0, (int)kNumFrameCounts),
                           ::testing::Range(0, (int)kNumLoopCounts),
                           ::testing::Range(0, (int)kNumEffectUuids),
                           ::testing::Range(0, (int)kNumPresets)));

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int status = RUN_ALL_TESTS();
    ALOGV("Test result = %d\n", status);
    return status;
}
