/*
 * Copyright 2024 The Android Open Source Project
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

#include <cstddef>
#include <unordered_map>
#define LOG_TAG "EffectHalVersionCompatibilityTest"

#include <EffectHalAidl.h>
#include <aidl/android/hardware/audio/effect/IEffect.h>
#include <aidl/android/hardware/audio/effect/IFactory.h>
#include <android-base/logging.h>
#include <android/binder_manager.h>
#include <android/binder_process.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <media/audiohal/EffectsFactoryHalInterface.h>
#include <system/audio_aidl_utils.h>
#include <system/audio_config.h>
#include <system/audio_effects/audio_effects_utils.h>
#include <system/audio_effects/effect_uuid.h>
#include <utils/Log.h>

using aidl::android::hardware::audio::effect::CommandId;
using aidl::android::hardware::audio::effect::Descriptor;
using aidl::android::hardware::audio::effect::IEffect;
using aidl::android::hardware::audio::effect::IFactory;
using aidl::android::hardware::audio::effect::kReopenSupportedVersion;
using aidl::android::hardware::audio::effect::Parameter;
using aidl::android::hardware::audio::effect::Processing;
using aidl::android::hardware::audio::effect::State;
using aidl::android::media::audio::common::AudioUuid;
using android::OK;
using android::sp;
using android::effect::EffectHalAidl;
using testing::_;
using testing::Eq;

namespace {

/**
 * Maps of parameter and the version it was introduced.
 */
// parameters defined directly in the Parameter union, except Parameter::specific (defined in
// kParamIdEffectVersionMap).
static const std::unordered_map<Parameter::Tag, int /* version */> kParamTagVersionMap = {
        {Parameter::common, 1},         {Parameter::deviceDescription, 1},
        {Parameter::mode, 1},           {Parameter::source, 1},
        {Parameter::offload, 1},        {Parameter::volumeStereo, 1},
        {Parameter::sourceMetadata, 2}, {Parameter::sinkMetadata, 2},
};

// Map of the version a specific effect type introduction
// Id tags defined Parameter::Id union, except Parameter::Id::commonTag (defined in
// kParamTagVersionMap).
static const std::unordered_map<Parameter::Id::Tag, int /* version */> kParamIdEffectVersionMap = {
        {Parameter::Id::vendorEffectTag, 1},
        {Parameter::Id::acousticEchoCancelerTag, 1},
        {Parameter::Id::automaticGainControlV1Tag, 1},
        {Parameter::Id::automaticGainControlV2Tag, 1},
        {Parameter::Id::bassBoostTag, 1},
        {Parameter::Id::downmixTag, 1},
        {Parameter::Id::dynamicsProcessingTag, 1},
        {Parameter::Id::environmentalReverbTag, 1},
        {Parameter::Id::equalizerTag, 1},
        {Parameter::Id::hapticGeneratorTag, 1},
        {Parameter::Id::loudnessEnhancerTag, 1},
        {Parameter::Id::noiseSuppressionTag, 1},
        {Parameter::Id::presetReverbTag, 1},
        {Parameter::Id::virtualizerTag, 1},
        {Parameter::Id::visualizerTag, 1},
        {Parameter::Id::volumeTag, 1},
        {Parameter::Id::spatializerTag, 2},
};
// Tags defined Parameter::Specific union.
static const std::unordered_map<Parameter::Specific::Tag, int /* version */>
        kParamEffectVersionMap = {
                {Parameter::Specific::vendorEffect, 1},
                {Parameter::Specific::acousticEchoCanceler, 1},
                {Parameter::Specific::automaticGainControlV1, 1},
                {Parameter::Specific::automaticGainControlV2, 1},
                {Parameter::Specific::bassBoost, 1},
                {Parameter::Specific::downmix, 1},
                {Parameter::Specific::dynamicsProcessing, 1},
                {Parameter::Specific::environmentalReverb, 1},
                {Parameter::Specific::equalizer, 1},
                {Parameter::Specific::hapticGenerator, 1},
                {Parameter::Specific::loudnessEnhancer, 1},
                {Parameter::Specific::noiseSuppression, 1},
                {Parameter::Specific::presetReverb, 1},
                {Parameter::Specific::virtualizer, 1},
                {Parameter::Specific::visualizer, 1},
                {Parameter::Specific::volume, 1},
                {Parameter::Specific::spatializer, 2},
};

class MockFactory : public IFactory {
  public:
    explicit MockFactory(int version) : IFactory(), mVersion(version) {}
    MOCK_METHOD(ndk::ScopedAStatus, queryEffects,
                (const std::optional<AudioUuid>& in_type_uuid,
                 const std::optional<AudioUuid>& in_impl_uuid,
                 const std::optional<AudioUuid>& in_proxy_uuid,
                 std::vector<Descriptor>* _aidl_return),
                (override));

    MOCK_METHOD(ndk::ScopedAStatus, queryProcessing,
                (const std::optional<Processing::Type>& in_type,
                 std::vector<Processing>* _aidl_return),
                (override));

    MOCK_METHOD(ndk::ScopedAStatus, createEffect,
                (const AudioUuid& in_impl_uuid, std::shared_ptr<IEffect>* _aidl_return),
                (override));

    MOCK_METHOD(ndk::ScopedAStatus, destroyEffect, (const std::shared_ptr<IEffect>& in_handle),
                (override));

    ndk::ScopedAStatus getInterfaceVersion(int32_t* _aidl_return) {
        *_aidl_return = mVersion;
        return ndk::ScopedAStatus::ok();
    }

    // these must be implemented but won't be used in this testing
    ::ndk::SpAIBinder asBinder() { return ::ndk::SpAIBinder(); }
    bool isRemote() { return false; }
    ::ndk::ScopedAStatus getInterfaceHash(std::string*) { return ndk::ScopedAStatus::ok(); }

  private:
    const int mVersion;
};

class MockEffect : public IEffect {
  public:
    explicit MockEffect(int version) : IEffect(), mVersion(version) {}
    MOCK_METHOD(ndk::ScopedAStatus, open,
                (const Parameter::Common& common,
                 const std::optional<Parameter::Specific>& specific,
                 IEffect::OpenEffectReturn* ret),
                (override));
    MOCK_METHOD(ndk::ScopedAStatus, close, (), (override));
    MOCK_METHOD(binder_status_t, dump, (int fd, const char** args, uint32_t numArgs), (override));
    MOCK_METHOD(ndk::ScopedAStatus, command, (CommandId id), (override));
    MOCK_METHOD(ndk::ScopedAStatus, getState, (State * state), (override));
    MOCK_METHOD(ndk::ScopedAStatus, getDescriptor, (Descriptor * desc), (override));
    MOCK_METHOD(ndk::ScopedAStatus, destroy, (), ());

    // reopen introduced in version kReopenSupportedVersion
    ndk::ScopedAStatus reopen(IEffect::OpenEffectReturn*) override {
        return mVersion < kReopenSupportedVersion
                       ? ndk::ScopedAStatus::fromStatus(STATUS_UNKNOWN_TRANSACTION)
                       : ndk::ScopedAStatus::ok();
    }

    // for all parameters introduced
    ndk::ScopedAStatus setParameter(const Parameter& param) override {
        const auto paramTag = param.getTag();
        switch (paramTag) {
            case Parameter::common:
            case Parameter::deviceDescription:
            case Parameter::mode:
            case Parameter::source:
            case Parameter::offload:
            case Parameter::volumeStereo:
            case Parameter::sinkMetadata:
                FALLTHROUGH_INTENDED;
            case Parameter::sourceMetadata: {
                if (kParamTagVersionMap.find(paramTag) != kParamTagVersionMap.end() &&
                    kParamTagVersionMap.at(paramTag) >= mVersion) {
                    return ndk::ScopedAStatus::ok();
                }
                break;
            }
            case Parameter::specific: {
                // TODO
                break;
            }
        }
        return ndk::ScopedAStatus::fromStatus(STATUS_BAD_VALUE);
    }

    /**
     * Only care about version compatibility here:
     * @return BAD_VALUE if a tag is not supported by current AIDL version.
     * @return OK if a tag is supported by current AIDL version.
     */
    ndk::ScopedAStatus getParameter(const Parameter::Id& id, Parameter*) override {
        const auto idTag = id.getTag();
        switch (idTag) {
            case Parameter::Id::commonTag: {
                const auto paramTag = id.get<Parameter::Id::commonTag>();
                if (kParamTagVersionMap.find(paramTag) != kParamTagVersionMap.end() &&
                    kParamTagVersionMap.at(paramTag) >= mVersion) {
                    return ndk::ScopedAStatus::ok();
                }
                break;
            }
            case Parameter::Id::vendorEffectTag:
            case Parameter::Id::acousticEchoCancelerTag:
            case Parameter::Id::automaticGainControlV1Tag:
            case Parameter::Id::automaticGainControlV2Tag:
            case Parameter::Id::bassBoostTag:
            case Parameter::Id::downmixTag:
            case Parameter::Id::dynamicsProcessingTag:
            case Parameter::Id::environmentalReverbTag:
            case Parameter::Id::equalizerTag:
            case Parameter::Id::hapticGeneratorTag:
            case Parameter::Id::loudnessEnhancerTag:
            case Parameter::Id::noiseSuppressionTag:
            case Parameter::Id::presetReverbTag:
            case Parameter::Id::virtualizerTag:
            case Parameter::Id::visualizerTag:
            case Parameter::Id::volumeTag:
                FALLTHROUGH_INTENDED;
            case Parameter::Id::spatializerTag: {
                if (kParamIdEffectVersionMap.find(idTag) != kParamIdEffectVersionMap.end() &&
                    kParamIdEffectVersionMap.at(idTag) >= mVersion) {
                    return ndk::ScopedAStatus::ok();
                }
                break;
            }
        }
        return ndk::ScopedAStatus::fromStatus(STATUS_BAD_VALUE);
    }

    ndk::ScopedAStatus getInterfaceVersion(int32_t* _aidl_return) {
        *_aidl_return = mVersion;
        return ndk::ScopedAStatus::ok();
    }

    // these must be implemented but won't be used in this testing
    ::ndk::SpAIBinder asBinder() { return ::ndk::SpAIBinder(); }
    bool isRemote() { return false; }
    ::ndk::ScopedAStatus getInterfaceHash(std::string*) { return ndk::ScopedAStatus::ok(); }

  private:
    const int mVersion;
};

static const std::vector<AudioUuid> kTestParamUUIDs = {
        ::aidl::android::hardware::audio::effect::getEffectTypeUuidAcousticEchoCanceler(),
        ::aidl::android::hardware::audio::effect::getEffectTypeUuidAutomaticGainControlV1(),
        ::aidl::android::hardware::audio::effect::getEffectTypeUuidAutomaticGainControlV2(),
        ::aidl::android::hardware::audio::effect::getEffectTypeUuidBassBoost(),
        ::aidl::android::hardware::audio::effect::getEffectTypeUuidDownmix(),
        ::aidl::android::hardware::audio::effect::getEffectTypeUuidDynamicsProcessing(),
        ::aidl::android::hardware::audio::effect::getEffectTypeUuidEnvReverb(),
        ::aidl::android::hardware::audio::effect::getEffectTypeUuidEqualizer(),
        ::aidl::android::hardware::audio::effect::getEffectTypeUuidHapticGenerator(),
        ::aidl::android::hardware::audio::effect::getEffectTypeUuidLoudnessEnhancer(),
        ::aidl::android::hardware::audio::effect::getEffectTypeUuidNoiseSuppression(),
        ::aidl::android::hardware::audio::effect::getEffectTypeUuidPresetReverb(),
        ::aidl::android::hardware::audio::effect::getEffectTypeUuidSpatializer(),
        ::aidl::android::hardware::audio::effect::getEffectTypeUuidVirtualizer(),
        ::aidl::android::hardware::audio::effect::getEffectTypeUuidVisualizer(),
        ::aidl::android::hardware::audio::effect::getEffectUuidNull(),
};
static const std::vector<int> kTestParamVersion = {1, 2};  // Effect AIDL HAL versions to test

enum ParamName { UUID, VERSION };
using TestParam = std::tuple<AudioUuid, int /* version */>;

class EffectHalVersionCompatibilityTest : public ::testing::TestWithParam<TestParam> {
  public:
    void SetUp() override {
        mMockFactory = ndk::SharedRefBase::make<MockFactory>(mVersion);
        ASSERT_NE(mMockFactory, nullptr);
        mMockEffect = ndk::SharedRefBase::make<MockEffect>(mVersion);
        ASSERT_NE(mMockEffect, nullptr);
        mEffectHalAidl = sp<EffectHalAidl>::make(mMockFactory, mMockEffect, 0, 0, mDesc, false);
        ASSERT_NE(mEffectHalAidl, nullptr);
    }

    void TearDown() override {
        EXPECT_CALL(*mMockFactory, destroyEffect(_));
        mEffectHalAidl.clear();
        mMockEffect.reset();
        mMockFactory.reset();
    }

  protected:
    const int mVersion = std::get<VERSION>(GetParam());
    const AudioUuid mTypeUuid = std::get<UUID>(GetParam());
    const Descriptor mDesc = {.common.id.type = mTypeUuid};
    std::shared_ptr<MockFactory> mMockFactory = nullptr;
    std::shared_ptr<MockEffect> mMockEffect = nullptr;
    sp<EffectHalAidl> mEffectHalAidl = nullptr;
};

TEST_P(EffectHalVersionCompatibilityTest, testEffectAidlHalCreateDestroy) {
    // do nothing
}

INSTANTIATE_TEST_SUITE_P(
        EffectHalVersionCompatibilityTestWithVersion, EffectHalVersionCompatibilityTest,
        ::testing::Combine(testing::ValuesIn(kTestParamUUIDs),
                           testing::ValuesIn(kTestParamVersion)),
        [](const testing::TestParamInfo<EffectHalVersionCompatibilityTest::ParamType>& info) {
            auto version = std::to_string(std::get<VERSION>(info.param));
            auto uuid = android::audio::utils::toString(std::get<UUID>(info.param));
            std::string name = "EffectHalVersionCompatibilityTest_V" + version + "_" + uuid;
            std::replace_if(
                    name.begin(), name.end(), [](const char c) { return !std::isalnum(c); }, '_');
            return name;
        });

}  // namespace