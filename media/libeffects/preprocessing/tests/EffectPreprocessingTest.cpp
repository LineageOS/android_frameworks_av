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

#include <getopt.h>
#include <stddef.h>
#include <stdint.h>
#include <tuple>
#include <vector>

#include <audio_effects/effect_aec.h>
#include <audio_effects/effect_agc.h>
#include <audio_effects/effect_agc2.h>
#include <audio_effects/effect_ns.h>
#include <log/log.h>

constexpr effect_uuid_t kAGCUuid = {
        0xaa8130e0, 0x66fc, 0x11e0, 0xbad0, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}};
constexpr effect_uuid_t kAGC2Uuid = {
        0x89f38e65, 0xd4d2, 0x4d64, 0xad0e, {0x2b, 0x3e, 0x79, 0x9e, 0xa8, 0x86}};
constexpr effect_uuid_t kAECUuid = {
        0xbb392ec0, 0x8d4d, 0x11e0, 0xa896, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}};
constexpr effect_uuid_t kNSUuid = {
        0xc06c8400, 0x8e06, 0x11e0, 0x9cb6, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}};

static bool isAGCEffect(const effect_uuid_t* uuid) {
    return uuid == &kAGCUuid;
}
static bool isAGC2Effect(const effect_uuid_t* uuid) {
    return uuid == &kAGC2Uuid;
}
static bool isAECEffect(const effect_uuid_t* uuid) {
    return uuid == &kAECUuid;
}
static bool isNSEffect(const effect_uuid_t* uuid) {
    return uuid == &kNSUuid;
}

constexpr int kAGCTargetLevels[] = {0, -300, -500, -1000, -3100};

constexpr int kAGCCompLevels[] = {0, -300, -500, -1000, -9000};

constexpr size_t kAGC2FixedDigitalGains[] = {0, 3, 10, 20, 49};

constexpr size_t kAGC2AdaptGigitalLevelEstimators[] = {0, 1};

constexpr size_t kAGC2ExtraSaturationMargins[] = {0, 3, 10, 20, 100};

constexpr size_t kAECEchoDelays[] = {0, 250, 500};

constexpr size_t kNSLevels[] = {0, 1, 2, 3};

struct AGCParams {
    int targetLevel;
    int compLevel;
};

struct AGC2Params {
    size_t fixedDigitalGain;
    size_t adaptDigiLevelEstimator;
    size_t extraSaturationMargin;
};

struct AECParams {
    size_t echoDelay;
};

struct NSParams {
    size_t level;
};

struct PreProcParams {
    const effect_uuid_t* uuid;
    union {
        AGCParams agcParams;
        AGC2Params agc2Params;
        AECParams aecParams;
        NSParams nsParams;
    };
};

// Create a list of pre-processing parameters to be used for testing
static const std::vector<PreProcParams> kPreProcParams = [] {
    std::vector<PreProcParams> result;

    for (const auto targetLevel : kAGCTargetLevels) {
        for (const auto compLevel : kAGCCompLevels) {
            AGCParams agcParams = {.targetLevel = targetLevel, .compLevel = compLevel};
            PreProcParams params = {.uuid = &kAGCUuid, .agcParams = agcParams};
            result.push_back(params);
        }
    }

    for (const auto fixedDigitalGain : kAGC2FixedDigitalGains) {
        for (const auto adaptDigiLevelEstimator : kAGC2AdaptGigitalLevelEstimators) {
            for (const auto extraSaturationMargin : kAGC2ExtraSaturationMargins) {
                AGC2Params agc2Params = {.fixedDigitalGain = fixedDigitalGain,
                                         .adaptDigiLevelEstimator = adaptDigiLevelEstimator,
                                         .extraSaturationMargin = extraSaturationMargin};
                PreProcParams params = {.uuid = &kAGC2Uuid, .agc2Params = agc2Params};
                result.push_back(params);
            }
        }
    }

    for (const auto echoDelay : kAECEchoDelays) {
        AECParams aecParams = {.echoDelay = echoDelay};
        PreProcParams params = {.uuid = &kAECUuid, .aecParams = aecParams};
        result.push_back(params);
    }

    for (const auto level : kNSLevels) {
        NSParams nsParams = {.level = level};
        PreProcParams params = {.uuid = &kNSUuid, .nsParams = nsParams};
        result.push_back(params);
    }
    return result;
}();

static const size_t kNumPreProcParams = std::size(kPreProcParams);

void setPreProcParams(const effect_uuid_t* uuid, EffectTestHelper& effect, size_t paramIdx) {
    const PreProcParams* params = &kPreProcParams[paramIdx];
    if (isAGCEffect(uuid)) {
        const AGCParams* agcParams = &params->agcParams;
        ASSERT_NO_FATAL_FAILURE(effect.setParam(AGC_PARAM_TARGET_LEVEL, agcParams->targetLevel));
        ASSERT_NO_FATAL_FAILURE(effect.setParam(AGC_PARAM_COMP_GAIN, agcParams->compLevel));
    } else if (isAGC2Effect(uuid)) {
        const AGC2Params* agc2Params = &params->agc2Params;
        ASSERT_NO_FATAL_FAILURE(
                effect.setParam(AGC2_PARAM_FIXED_DIGITAL_GAIN, agc2Params->fixedDigitalGain));
        ASSERT_NO_FATAL_FAILURE(effect.setParam(AGC2_PARAM_ADAPT_DIGI_LEVEL_ESTIMATOR,
                                                agc2Params->adaptDigiLevelEstimator));
        ASSERT_NO_FATAL_FAILURE(effect.setParam(AGC2_PARAM_ADAPT_DIGI_EXTRA_SATURATION_MARGIN,
                                                agc2Params->extraSaturationMargin));
    } else if (isAECEffect(uuid)) {
        const AECParams* aecParams = &params->aecParams;
        ASSERT_NO_FATAL_FAILURE(effect.setParam(AEC_PARAM_ECHO_DELAY, aecParams->echoDelay));
    } else if (isNSEffect(uuid)) {
        const NSParams* nsParams = &params->nsParams;
        ASSERT_NO_FATAL_FAILURE(effect.setParam(NS_PARAM_LEVEL, nsParams->level));
    }
}

typedef std::tuple<int, int, int, int> SingleEffectTestParam;
class SingleEffectTest : public ::testing::TestWithParam<SingleEffectTestParam> {
  public:
    SingleEffectTest()
        : mSampleRate(EffectTestHelper::kSampleRates[std::get<1>(GetParam())]),
          mFrameCount(mSampleRate * EffectTestHelper::kTenMilliSecVal),
          mLoopCount(EffectTestHelper::kLoopCounts[std::get<2>(GetParam())]),
          mTotalFrameCount(mFrameCount * mLoopCount),
          mChMask(EffectTestHelper::kChMasks[std::get<0>(GetParam())]),
          mChannelCount(audio_channel_count_from_in_mask(mChMask)),
          mParamIdx(std::get<3>(GetParam())),
          mUuid(kPreProcParams[mParamIdx].uuid){};

    const size_t mSampleRate;
    const size_t mFrameCount;
    const size_t mLoopCount;
    const size_t mTotalFrameCount;
    const size_t mChMask;
    const size_t mChannelCount;
    const size_t mParamIdx;
    const effect_uuid_t* mUuid;
};

// Tests applying a single effect
TEST_P(SingleEffectTest, SimpleProcess) {
    SCOPED_TRACE(testing::Message() << " chMask: " << mChMask << " sampleRate: " << mSampleRate
                                    << " loopCount: " << mLoopCount << " paramIdx " << mParamIdx);

    EffectTestHelper effect(mUuid, mChMask, mSampleRate, mLoopCount);

    ASSERT_NO_FATAL_FAILURE(effect.createEffect());
    ASSERT_NO_FATAL_FAILURE(effect.setConfig(isAECEffect(mUuid)));
    ASSERT_NO_FATAL_FAILURE(setPreProcParams(mUuid, effect, mParamIdx));

    // Initialize input buffer with deterministic pseudo-random values
    std::vector<int16_t> input(mTotalFrameCount * mChannelCount);
    std::vector<int16_t> output(mTotalFrameCount * mChannelCount);
    std::vector<int16_t> farInput(mTotalFrameCount * mChannelCount);
    std::minstd_rand gen(mChMask);
    std::uniform_int_distribution<int16_t> dis(INT16_MIN, INT16_MAX);
    for (auto& in : input) {
        in = dis(gen);
    }
    if (isAECEffect(mUuid)) {
        for (auto& farIn : farInput) {
            farIn = dis(gen);
        }
    }
    ASSERT_NO_FATAL_FAILURE(effect.process(input.data(), output.data(), isAECEffect(mUuid)));
    if (isAECEffect(mUuid)) {
        ASSERT_NO_FATAL_FAILURE(effect.process_reverse(farInput.data(), output.data()));
    }
    ASSERT_NO_FATAL_FAILURE(effect.releaseEffect());
}

INSTANTIATE_TEST_SUITE_P(
        PreProcTestAll, SingleEffectTest,
        ::testing::Combine(::testing::Range(0, (int)EffectTestHelper::kNumChMasks),
                           ::testing::Range(0, (int)EffectTestHelper::kNumSampleRates),
                           ::testing::Range(0, (int)EffectTestHelper::kNumLoopCounts),
                           ::testing::Range(0, (int)kNumPreProcParams)));

typedef std::tuple<int, int, int> SingleEffectComparisonTestParam;
class SingleEffectComparisonTest
    : public ::testing::TestWithParam<SingleEffectComparisonTestParam> {
  public:
    SingleEffectComparisonTest()
        : mSampleRate(EffectTestHelper::kSampleRates[std::get<0>(GetParam())]),
          mFrameCount(mSampleRate * EffectTestHelper::kTenMilliSecVal),
          mLoopCount(EffectTestHelper::kLoopCounts[std::get<1>(GetParam())]),
          mTotalFrameCount(mFrameCount * mLoopCount),
          mParamIdx(std::get<2>(GetParam())),
          mUuid(kPreProcParams[mParamIdx].uuid){};

    const size_t mSampleRate;
    const size_t mFrameCount;
    const size_t mLoopCount;
    const size_t mTotalFrameCount;
    const size_t mParamIdx;
    const effect_uuid_t* mUuid;
};

// Compares first channel in multi-channel output to mono output when same effect is applied
TEST_P(SingleEffectComparisonTest, SimpleProcess) {
    SCOPED_TRACE(testing::Message() << " sampleRate: " << mSampleRate
                                    << " loopCount: " << mLoopCount << " paramIdx " << mParamIdx);

    // Initialize mono input buffer with deterministic pseudo-random values
    std::vector<int16_t> monoInput(mTotalFrameCount);
    std::vector<int16_t> monoFarInput(mTotalFrameCount);

    std::minstd_rand gen(mSampleRate);
    std::uniform_int_distribution<int16_t> dis(INT16_MIN, INT16_MAX);
    for (auto& in : monoInput) {
        in = dis(gen);
    }
    if (isAECEffect(mUuid)) {
        for (auto& farIn : monoFarInput) {
            farIn = dis(gen);
        }
    }

    // Apply effect on mono channel
    EffectTestHelper monoEffect(mUuid, AUDIO_CHANNEL_INDEX_MASK_1, mSampleRate, mLoopCount);

    ASSERT_NO_FATAL_FAILURE(monoEffect.createEffect());
    ASSERT_NO_FATAL_FAILURE(monoEffect.setConfig(isAECEffect(mUuid)));
    ASSERT_NO_FATAL_FAILURE(setPreProcParams(mUuid, monoEffect, mParamIdx));

    std::vector<int16_t> monoOutput(mTotalFrameCount);
    ASSERT_NO_FATAL_FAILURE(
            monoEffect.process(monoInput.data(), monoOutput.data(), isAECEffect(mUuid)));
    if (isAECEffect(mUuid)) {
        ASSERT_NO_FATAL_FAILURE(monoEffect.process_reverse(monoFarInput.data(), monoOutput.data()));
    }
    ASSERT_NO_FATAL_FAILURE(monoEffect.releaseEffect());

    for (size_t chMask : EffectTestHelper::kChMasks) {
        size_t channelCount = audio_channel_count_from_in_mask(chMask);

        EffectTestHelper testEffect(mUuid, chMask, mSampleRate, mLoopCount);

        ASSERT_NO_FATAL_FAILURE(testEffect.createEffect());
        ASSERT_NO_FATAL_FAILURE(testEffect.setConfig(isAECEffect(mUuid)));
        ASSERT_NO_FATAL_FAILURE(setPreProcParams(mUuid, testEffect, mParamIdx));

        std::vector<int16_t> testInput(mTotalFrameCount * channelCount);
        std::vector<int16_t> testFarInput(mTotalFrameCount * channelCount);

        // Repeat mono channel data to all the channels
        // adjust_channels() zero fills channels > 2, hence can't be used here
        for (size_t i = 0; i < mTotalFrameCount; ++i) {
            auto* fpInput = &testInput[i * channelCount];
            std::fill(fpInput, fpInput + channelCount, monoInput[i]);
        }
        if (isAECEffect(mUuid)) {
            for (size_t i = 0; i < mTotalFrameCount; ++i) {
                auto* fpFarInput = &testFarInput[i * channelCount];
                std::fill(fpFarInput, fpFarInput + channelCount, monoFarInput[i]);
            }
        }

        std::vector<int16_t> testOutput(mTotalFrameCount * channelCount);
        ASSERT_NO_FATAL_FAILURE(
                testEffect.process(testInput.data(), testOutput.data(), isAECEffect(mUuid)));
        if (isAECEffect(mUuid)) {
            ASSERT_NO_FATAL_FAILURE(
                    testEffect.process_reverse(testFarInput.data(), testOutput.data()));
        }
        ASSERT_NO_FATAL_FAILURE(testEffect.releaseEffect());

        // Adjust the test output to mono channel
        std::vector<int16_t> monoTestOutput(mTotalFrameCount);
        adjust_channels(testOutput.data(), channelCount, monoTestOutput.data(), FCC_1,
                        sizeof(int16_t), mTotalFrameCount * sizeof(int16_t) * channelCount);

        ASSERT_EQ(0, memcmp(monoOutput.data(), monoTestOutput.data(),
                            mTotalFrameCount * sizeof(int16_t)))
                << "Mono channel output does not match with reference output \n";
    }
}

INSTANTIATE_TEST_SUITE_P(
        PreProcTestAll, SingleEffectComparisonTest,
        ::testing::Combine(::testing::Range(0, (int)EffectTestHelper::kNumSampleRates),
                           ::testing::Range(0, (int)EffectTestHelper::kNumLoopCounts),
                           ::testing::Range(0, (int)kNumPreProcParams)));

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int status = RUN_ALL_TESTS();
    ALOGV("Test result = %d", status);
    return status;
}
