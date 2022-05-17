/*
 * Copyright 2022 The Android Open Source Project
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

#define LOG_TAG "SpatializerTest"

#include <system/audio_effects/effect_spatializer.h>
#include "EffectTestHelper.h"

using namespace android;

// relying on dlsym to fill the interface context
audio_effect_library_t AUDIO_EFFECT_LIBRARY_INFO_SYM = [] {
    audio_effect_library_t symbol{};
    void* effectLib = dlopen("libspatialaudio.so", RTLD_NOW);
    if (effectLib) {
        audio_effect_library_t* effectInterface =
                (audio_effect_library_t*)dlsym(effectLib, AUDIO_EFFECT_LIBRARY_INFO_SYM_AS_STR);
        if (effectInterface == nullptr) {
            ALOGE("dlsym failed: %s", dlerror());
            exit(-1);
        }
        symbol = (audio_effect_library_t)(*effectInterface);
    } else {
        ALOGE("dlopen failed: %s", dlerror());
        exit(-1);
    }
    return symbol;
}();

// channel masks
constexpr audio_channel_mask_t kSpatializerChMasks[] = {
        AUDIO_CHANNEL_OUT_5POINT1,
};
constexpr size_t kNumSpatializerChMasks = std::size(kSpatializerChMasks);

// sampleRates
// TODO(b/234170025): Add all sampling rates once they are handled by spatializer
constexpr int kSpatializerSampleRates[] = {44100, 48000, 96000};
constexpr size_t kNumSpatializerSampleRates = std::size(kSpatializerSampleRates);

// frame counts
// TODO(b/234620538): Add sizes smaller than 80 once they are handled by spatializer
constexpr size_t kSpatializerFrameCounts[] = {4800, 1920, 480, 80};
constexpr size_t kNumSpatializerFrameCounts = std::size(kSpatializerFrameCounts);

// effect uuids
constexpr effect_uuid_t kSpatializerEffectUuids[] = {
        {0xcc4677de, 0xff72, 0x11eb, 0x9a03, {0x02, 0x42, 0xac, 0x13, 0x00, 0x03}},
};
const size_t kNumSpatializerEffectUuids = std::size(kSpatializerEffectUuids);

constexpr float kMinAmplitude = -1.0f;
constexpr float kMaxAmplitude = 1.0f;
constexpr float kSNRThreshold = 100.0f;
constexpr size_t kNumBufferSplits = 2;

using SingleEffectTestParam = std::tuple<int, int, int, int, int>;

class SingleEffectTest : public ::testing::TestWithParam<SingleEffectTestParam> {
  public:
    SingleEffectTest()
        : mInputChMask(kSpatializerChMasks[std::get<0>(GetParam())]),
          mInputChannelCount(audio_channel_count_from_out_mask(mInputChMask)),
          mOutputChMask(AUDIO_CHANNEL_OUT_STEREO),
          mOutputChannelCount(audio_channel_count_from_out_mask(mOutputChMask)),
          mSampleRate(kSpatializerSampleRates[std::get<1>(GetParam())]),
          mFrameCount(kSpatializerFrameCounts[std::get<2>(GetParam())]),
          mLoopCount(EffectTestHelper::kLoopCounts[std::get<3>(GetParam())]),
          mTotalFrameCount(mFrameCount * mLoopCount),
          mUuid(&kSpatializerEffectUuids[std::get<4>(GetParam())]) {}
    void SetUp() override {
        ASSERT_EQ(AUDIO_EFFECT_LIBRARY_TAG, AUDIO_EFFECT_LIBRARY_INFO_SYM.tag)
                << "Invalid effect tag";
    }
    const size_t mInputChMask;
    const size_t mInputChannelCount;
    const size_t mOutputChMask;
    const size_t mOutputChannelCount;
    const size_t mSampleRate;
    const size_t mFrameCount;
    const size_t mLoopCount;
    const size_t mTotalFrameCount;
    const effect_uuid_t* mUuid;
};

// Test basic spatializer functionality (does not crash) for various combinations of sampling
// rates, channel masks and frame counts.
TEST_P(SingleEffectTest, SimpleProcess) {
    SCOPED_TRACE(testing::Message()
                 << "chMask: " << mInputChMask << " sampleRate: " << mSampleRate);

    EffectTestHelper effect(mUuid, mInputChMask, mOutputChMask, mSampleRate, mFrameCount,
                            mLoopCount);
    ASSERT_NO_FATAL_FAILURE(effect.createEffect());
    ASSERT_NO_FATAL_FAILURE(effect.setConfig());

    // Initialize input buffer with deterministic pseudo-random values
    std::vector<float> input(mTotalFrameCount * mInputChannelCount);
    std::vector<float> output(mTotalFrameCount * mOutputChannelCount);
    std::minstd_rand gen(mInputChMask);
    std::uniform_real_distribution<> dis(kMinAmplitude, kMaxAmplitude);
    for (auto& in : input) {
        in = dis(gen);
    }
    ASSERT_NO_FATAL_FAILURE(effect.process(input.data(), output.data()));
    ASSERT_NO_FATAL_FAILURE(effect.releaseEffect());
}

INSTANTIATE_TEST_SUITE_P(SpatializerTest, SingleEffectTest,
                         ::testing::Combine(::testing::Range(0, (int)kNumSpatializerChMasks),
                                            ::testing::Range(0, (int)kNumSpatializerSampleRates),
                                            ::testing::Range(0, (int)kNumSpatializerFrameCounts),
                                            ::testing::Range(0,
                                                             (int)EffectTestHelper::kNumLoopCounts),
                                            ::testing::Range(0, (int)kNumSpatializerEffectUuids)));

using SingleEffectComparisonTestParam = std::tuple<int, int, int>;

class SingleEffectComparisonTest
    : public ::testing::TestWithParam<SingleEffectComparisonTestParam> {
  public:
    SingleEffectComparisonTest()
        : mInputChMask(kSpatializerChMasks[std::get<0>(GetParam())]),
          mInputChannelCount(audio_channel_count_from_out_mask(mInputChMask)),
          mOutputChMask(AUDIO_CHANNEL_OUT_STEREO),
          mOutputChannelCount(audio_channel_count_from_out_mask(mOutputChMask)),
          mSampleRate(kSpatializerSampleRates[std::get<1>(GetParam())]),
          mUuid(&kSpatializerEffectUuids[std::get<2>(GetParam())]) {}

    const size_t mInputChMask;
    const size_t mInputChannelCount;
    const size_t mOutputChMask;
    const size_t mOutputChannelCount;
    const size_t mSampleRate;
    const effect_uuid_t* mUuid;
};

// Ensure that effect produces similar output when an input is fed in a single call
// or called multiples times with buffer split into smaller parts

// TODO(b/234619903): This is currently disabled as output from the spatializer has
// an algorithm delay that varies with frame count and hence makes it tricky to
// compare output from two cases with different frame counts.
// Feed valid input to spatializer and dump the output to verify spatializer is being
// correctly initialized and once that is verified, enable the following
TEST_P(SingleEffectComparisonTest, DISABLED_SimpleProcess) {
    SCOPED_TRACE(testing::Message()
                 << "chMask: " << mInputChMask << " sampleRate: " << mSampleRate);
    int testDurationMs = 20; // 20 ms
    int testFrameCount = (mSampleRate * testDurationMs) / 1000;
    int totalFrameCount = testFrameCount * kNumBufferSplits;
    size_t totalInSamples = totalFrameCount * mInputChannelCount;
    size_t totalOutSamples = totalFrameCount * mOutputChannelCount;
    std::vector<float> input(totalInSamples);
    std::vector<float> outRef(totalOutSamples);
    std::vector<float> outTest(totalOutSamples);

    // Initialize input buffer with deterministic pseudo-random values
    std::minstd_rand gen(mInputChMask);
    std::uniform_real_distribution<> dis(kMinAmplitude, kMaxAmplitude);
    for (auto& in : input) {
        in = dis(gen);
    }

    EffectTestHelper refEffect(mUuid, mInputChMask, mOutputChMask, mSampleRate, totalFrameCount, 1);
    ASSERT_NO_FATAL_FAILURE(refEffect.createEffect());
    ASSERT_NO_FATAL_FAILURE(refEffect.setConfig());
    ASSERT_NO_FATAL_FAILURE(refEffect.process(input.data(), outRef.data()));
    ASSERT_NO_FATAL_FAILURE(refEffect.releaseEffect());

    EffectTestHelper testEffect(mUuid, mInputChMask, mOutputChMask, mSampleRate,
                                totalFrameCount / kNumBufferSplits, kNumBufferSplits);
    ASSERT_NO_FATAL_FAILURE(testEffect.createEffect());
    ASSERT_NO_FATAL_FAILURE(testEffect.setConfig());
    ASSERT_NO_FATAL_FAILURE(testEffect.process(input.data(), outTest.data()));
    ASSERT_NO_FATAL_FAILURE(testEffect.releaseEffect());

    float snr = computeSnr(outTest.data(), outRef.data(), totalOutSamples);
    ASSERT_GT(snr, kSNRThreshold) << "SNR between reference and test output " << snr
                                  << " is lower than required " << kSNRThreshold;
}

INSTANTIATE_TEST_SUITE_P(SpatializerTest, SingleEffectComparisonTest,
                         ::testing::Combine(::testing::Range(0, (int)kNumSpatializerChMasks),
                                            ::testing::Range(0, (int)kNumSpatializerSampleRates),
                                            ::testing::Range(0, (int)kNumSpatializerEffectUuids)));

// This test checks if get/set Spatializer effect params are in accordance with documentation. The
// test doesn't validate the functionality of the params configured. It only checks the return
// status of API calls.
TEST(ParameterTests, CheckParameterSupport) {
    EffectTestHelper effect(&kSpatializerEffectUuids[0], kSpatializerChMasks[0],
                            AUDIO_CHANNEL_OUT_STEREO, kSpatializerSampleRates[0],
                            kSpatializerFrameCounts[0], EffectTestHelper::kLoopCounts[0]);
    ASSERT_NO_FATAL_FAILURE(effect.createEffect());

    // capture list of channel masks supported
    std::vector<audio_channel_mask_t> channelMasks;
    int status = effect.getParam<true>(SPATIALIZER_PARAM_SUPPORTED_CHANNEL_MASKS, channelMasks);
    EXPECT_EQ(status, 0) << "get Param returned an error " << status;
    if (!status) {
        EXPECT_EQ(1, channelMasks.size());
        EXPECT_EQ(AUDIO_CHANNEL_OUT_5POINT1, channelMasks[0]);
    }

    // capture list of spatialization levels supported
    std::vector<int8_t> spatializationLevels;
    status = effect.getParam<true>(SPATIALIZER_PARAM_SUPPORTED_LEVELS, spatializationLevels);
    EXPECT_EQ(status, 0) << "get Param returned an error " << status;
    if (!status) {
        EXPECT_EQ(1, spatializationLevels.size());
        EXPECT_EQ(SPATIALIZATION_LEVEL_MULTICHANNEL, spatializationLevels[0]);
    }

    // capture list of spatialization modes supported
    std::vector<int8_t> spatializationModes;
    status = effect.getParam<true>(SPATIALIZER_PARAM_SUPPORTED_SPATIALIZATION_MODES,
                                   spatializationModes);
    EXPECT_EQ(status, 0) << "get Param returned an error " << status;
    if (!status) {
        EXPECT_EQ(1, spatializationModes.size());
        EXPECT_EQ(SPATIALIZATION_MODE_BINAURAL, spatializationModes[0]);
    }

    // check if head tracking is supported
    std::vector<int8_t> headTracking;
    status = effect.getParam<false>(SPATIALIZER_PARAM_HEADTRACKING_SUPPORTED, headTracking);
    EXPECT_EQ(status, 0) << "get Param returned an error " << status;
    if (!status) {
        EXPECT_EQ(1, headTracking.size());
        EXPECT_EQ(true, headTracking[0]);
    }

    // verify spatialization level setting
    std::vector<int8_t> level;
    status = effect.getParam<false>(SPATIALIZER_PARAM_LEVEL, level);
    EXPECT_EQ(status, 0) << "get Param returned an error " << status;
    if (!status) {
        EXPECT_EQ(1, level.size());
        EXPECT_EQ(SPATIALIZATION_LEVEL_NONE, level[0]);
    }

    ASSERT_NO_FATAL_FAILURE(effect.setConfig());

    status = effect.getParam<false>(SPATIALIZER_PARAM_LEVEL, level);
    EXPECT_EQ(status, 0) << "get Param returned an error " << status;
    if (!status) {
        EXPECT_EQ(1, level.size());
        EXPECT_EQ(SPATIALIZATION_LEVEL_MULTICHANNEL, level[0]);
    }

    // try setting unsupported parameters
    level.clear();
    level.push_back(SPATIALIZATION_LEVEL_MCHAN_BED_PLUS_OBJECTS);
    ASSERT_EQ(1, level.size());
    EXPECT_NE(0, effect.setParam(SPATIALIZER_PARAM_LEVEL, level));

    // Ensure that unsupported level isn't set by above setParam
    status = effect.getParam<false>(SPATIALIZER_PARAM_LEVEL, level);
    EXPECT_EQ(status, 0) << "get Param returned an error " << status;
    if (!status) {
        EXPECT_EQ(1, level.size());
        EXPECT_EQ(SPATIALIZATION_LEVEL_MULTICHANNEL, level[0]);
    }

    std::vector<float> hingeAngle = {3.1415f};
    ASSERT_EQ(1, hingeAngle.size());
    EXPECT_NE(0, effect.setParam(SPATIALIZER_PARAM_HINGE_ANGLE, hingeAngle));

    std::vector<int8_t> headTrackingMode = {2};  // RELATIVE_WORLD
    ASSERT_EQ(1, headTrackingMode.size());
    EXPECT_NE(0, effect.setParam(SPATIALIZER_PARAM_HEADTRACKING_MODE, headTrackingMode));

    // try setting supported parameters
    std::vector<float> vectorFloat = {0.1, 0.2, 0.15, 0.04, 2.23, 3.14};
    ASSERT_EQ(6, vectorFloat.size());
    EXPECT_EQ(0, effect.setParam(SPATIALIZER_PARAM_HEAD_TO_STAGE, vectorFloat));

    ASSERT_NO_FATAL_FAILURE(effect.releaseEffect());
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int status = RUN_ALL_TESTS();
    ALOGD("Test result = %d\n", status);
    return status;
}
