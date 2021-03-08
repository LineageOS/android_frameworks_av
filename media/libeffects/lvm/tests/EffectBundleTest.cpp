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
using namespace android;

// Update isBassBoost, if the order of effects is updated
constexpr effect_uuid_t kEffectUuids[] = {
        // NXP SW BassBoost
        {0x8631f300, 0x72e2, 0x11df, 0xb57e, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}},
        // NXP SW Virtualizer
        {0x1d4033c0, 0x8557, 0x11df, 0x9f2d, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}},
        // NXP SW Equalizer
        {0xce772f20, 0x847d, 0x11df, 0xbb17, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}},
        // NXP SW Volume
        {0x119341a0, 0x8469, 0x11df, 0x81f9, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}},
};

static bool isBassBoost(const effect_uuid_t* uuid) {
    // Update this, if the order of effects in kEffectUuids is updated
    return uuid == &kEffectUuids[0];
}

constexpr size_t kNumEffectUuids = std::size(kEffectUuids);

typedef std::tuple<int, int, int, int, int> SingleEffectTestParam;
class SingleEffectTest : public ::testing::TestWithParam<SingleEffectTestParam> {
  public:
    SingleEffectTest()
        : mChMask(EffectTestHelper::kChMasks[std::get<0>(GetParam())]),
          mChannelCount(audio_channel_count_from_out_mask(mChMask)),
          mSampleRate(EffectTestHelper::kSampleRates[std::get<1>(GetParam())]),
          mFrameCount(EffectTestHelper::kFrameCounts[std::get<2>(GetParam())]),
          mLoopCount(EffectTestHelper::kLoopCounts[std::get<3>(GetParam())]),
          mTotalFrameCount(mFrameCount * mLoopCount),
          mUuid(&kEffectUuids[std::get<4>(GetParam())]) {}

    const size_t mChMask;
    const size_t mChannelCount;
    const size_t mSampleRate;
    const size_t mFrameCount;
    const size_t mLoopCount;
    const size_t mTotalFrameCount;
    const effect_uuid_t* mUuid;
};

// Tests applying a single effect
TEST_P(SingleEffectTest, SimpleProcess) {
    SCOPED_TRACE(testing::Message()
                 << "chMask: " << mChMask << " sampleRate: " << mSampleRate
                 << " frameCount: " << mFrameCount << " loopCount: " << mLoopCount);

    EffectTestHelper effect(mUuid, mChMask, mChMask, mSampleRate, mFrameCount, mLoopCount);

    ASSERT_NO_FATAL_FAILURE(effect.createEffect());
    ASSERT_NO_FATAL_FAILURE(effect.setConfig());

    // Initialize input buffer with deterministic pseudo-random values
    std::vector<float> input(mTotalFrameCount * mChannelCount);
    std::vector<float> output(mTotalFrameCount * mChannelCount);
    std::minstd_rand gen(mChMask);
    std::uniform_real_distribution<> dis(-1.0f, 1.0f);
    for (auto& in : input) {
        in = dis(gen);
    }
    ASSERT_NO_FATAL_FAILURE(effect.process(input.data(), output.data()));
    ASSERT_NO_FATAL_FAILURE(effect.releaseEffect());
}

INSTANTIATE_TEST_SUITE_P(
        EffectBundleTestAll, SingleEffectTest,
        ::testing::Combine(::testing::Range(0, (int)EffectTestHelper::kNumChMasks),
                           ::testing::Range(0, (int)EffectTestHelper::kNumSampleRates),
                           ::testing::Range(0, (int)EffectTestHelper::kNumFrameCounts),
                           ::testing::Range(0, (int)EffectTestHelper::kNumLoopCounts),
                           ::testing::Range(0, (int)kNumEffectUuids)));

typedef std::tuple<int, int, int, int> SingleEffectComparisonTestParam;
class SingleEffectComparisonTest
    : public ::testing::TestWithParam<SingleEffectComparisonTestParam> {
  public:
    SingleEffectComparisonTest()
        : mSampleRate(EffectTestHelper::kSampleRates[std::get<0>(GetParam())]),
          mFrameCount(EffectTestHelper::kFrameCounts[std::get<1>(GetParam())]),
          mLoopCount(EffectTestHelper::kLoopCounts[std::get<2>(GetParam())]),
          mTotalFrameCount(mFrameCount * mLoopCount),
          mUuid(&kEffectUuids[std::get<3>(GetParam())]) {}

    const size_t mSampleRate;
    const size_t mFrameCount;
    const size_t mLoopCount;
    const size_t mTotalFrameCount;
    const effect_uuid_t* mUuid;
};

// Compares first two channels in multi-channel output to stereo output when same effect is applied
TEST_P(SingleEffectComparisonTest, SimpleProcess) {
    SCOPED_TRACE(testing::Message() << " sampleRate: " << mSampleRate << " frameCount: "
                                    << mFrameCount << " loopCount: " << mLoopCount);

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
    EffectTestHelper stereoEffect(mUuid, AUDIO_CHANNEL_OUT_STEREO, AUDIO_CHANNEL_OUT_STEREO,
                                  mSampleRate, mFrameCount, mLoopCount);

    ASSERT_NO_FATAL_FAILURE(stereoEffect.createEffect());
    ASSERT_NO_FATAL_FAILURE(stereoEffect.setConfig());

    std::vector<float> stereoOutput(mTotalFrameCount * FCC_2);
    ASSERT_NO_FATAL_FAILURE(stereoEffect.process(stereoInput.data(), stereoOutput.data()));
    ASSERT_NO_FATAL_FAILURE(stereoEffect.releaseEffect());

    // Convert stereo float data to stereo int16_t to be used as reference
    std::vector<int16_t> stereoRefI16(mTotalFrameCount * FCC_2);
    memcpy_to_i16_from_float(stereoRefI16.data(), stereoOutput.data(), mTotalFrameCount * FCC_2);

    for (size_t chMask : EffectTestHelper::kChMasks) {
        size_t channelCount = audio_channel_count_from_out_mask(chMask);
        EffectTestHelper testEffect(mUuid, chMask, chMask, mSampleRate, mFrameCount, mLoopCount);

        ASSERT_NO_FATAL_FAILURE(testEffect.createEffect());
        ASSERT_NO_FATAL_FAILURE(testEffect.setConfig());

        std::vector<float> testInput(mTotalFrameCount * channelCount);

        // Repeat mono channel data to all the channels
        // adjust_channels() zero fills channels > 2, hence can't be used here
        for (size_t i = 0; i < mTotalFrameCount; ++i) {
            auto* fp = &testInput[i * channelCount];
            std::fill(fp, fp + channelCount, monoInput[i]);
        }

        std::vector<float> testOutput(mTotalFrameCount * channelCount);
        ASSERT_NO_FATAL_FAILURE(testEffect.process(testInput.data(), testOutput.data()));
        ASSERT_NO_FATAL_FAILURE(testEffect.releaseEffect());

        // Extract first two channels
        std::vector<float> stereoTestOutput(mTotalFrameCount * FCC_2);
        adjust_channels(testOutput.data(), channelCount, stereoTestOutput.data(), FCC_2,
                        sizeof(float), mTotalFrameCount * sizeof(float) * channelCount);

        // Convert the test data to int16_t
        std::vector<int16_t> stereoTestI16(mTotalFrameCount * FCC_2);
        memcpy_to_i16_from_float(stereoTestI16.data(), stereoTestOutput.data(),
                                 mTotalFrameCount * FCC_2);

        if (isBassBoost(mUuid)) {
            // SNR must be above the threshold
            float snr = computeSnr<int16_t>(stereoRefI16.data(), stereoTestI16.data(),
                                            mTotalFrameCount * FCC_2);
            ASSERT_GT(snr, EffectTestHelper::kSNRThreshold)
                    << "SNR " << snr << "is lower than " << EffectTestHelper::kSNRThreshold;
        } else {
            ASSERT_EQ(0,
                      memcmp(stereoRefI16.data(), stereoTestI16.data(), mTotalFrameCount * FCC_2))
                    << "First two channels do not match with stereo output \n";
        }
    }
}

INSTANTIATE_TEST_SUITE_P(
        EffectBundleTestAll, SingleEffectComparisonTest,
        ::testing::Combine(::testing::Range(0, (int)EffectTestHelper::kNumSampleRates),
                           ::testing::Range(0, (int)EffectTestHelper::kNumFrameCounts),
                           ::testing::Range(0, (int)EffectTestHelper::kNumLoopCounts),
                           ::testing::Range(0, (int)kNumEffectUuids)));

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int status = RUN_ALL_TESTS();
    ALOGV("Test result = %d\n", status);
    return status;
}
