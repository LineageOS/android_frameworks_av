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

//#define LOG_NDEBUG 0
#define LOG_TAG "AudioClientSerializationTests"

#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <vector>

#include <android_audio_policy_configuration_V7_0-enums.h>
#include <gtest/gtest.h>
#include <media/AudioPolicy.h>
#include <media/AudioProductStrategy.h>
#include <media/AudioVolumeGroup.h>
#include <media/VolumeGroupAttributes.h>
#include <system/audio.h>
#include <xsdc/XsdcSupport.h>

#include "test_execution_tracer.h"

using namespace android;
namespace xsd {
using namespace ::android::audio::policy::configuration::V7_0;
}

template <typename T, typename X, typename FUNC>
std::vector<T> getFlags(const xsdc_enum_range<X>& range, const FUNC& func,
                        const std::string& findString = {}) {
    std::vector<T> vec;
    for (const auto& xsdEnumVal : range) {
        T enumVal;
        std::string enumString = toString(xsdEnumVal);
        if (enumString.find(findString) != std::string::npos &&
            func(enumString.c_str(), &enumVal)) {
            vec.push_back(enumVal);
        }
    }
    return vec;
}

static const std::vector<audio_usage_t> kUsages =
        getFlags<audio_usage_t, xsd::AudioUsage, decltype(audio_usage_from_string)>(
                xsdc_enum_range<xsd::AudioUsage>{}, audio_usage_from_string);

static const std::vector<audio_content_type_t> kContentType =
        getFlags<audio_content_type_t, xsd::AudioContentType,
                 decltype(audio_content_type_from_string)>(xsdc_enum_range<xsd::AudioContentType>{},
                                                           audio_content_type_from_string);

static const std::vector<audio_source_t> kInputSources =
        getFlags<audio_source_t, xsd::AudioSource, decltype(audio_source_from_string)>(
                xsdc_enum_range<xsd::AudioSource>{}, audio_source_from_string);

static const std::vector<audio_stream_type_t> kStreamtypes =
        getFlags<audio_stream_type_t, xsd::AudioStreamType,
                 decltype(audio_stream_type_from_string)>(xsdc_enum_range<xsd::AudioStreamType>{},
                                                          audio_stream_type_from_string);

static const std::vector<uint32_t> kMixMatchRules = {RULE_MATCH_ATTRIBUTE_USAGE,
                                                     RULE_EXCLUDE_ATTRIBUTE_USAGE,
                                                     RULE_MATCH_ATTRIBUTE_CAPTURE_PRESET,
                                                     RULE_EXCLUDE_ATTRIBUTE_CAPTURE_PRESET,
                                                     RULE_MATCH_UID,
                                                     RULE_EXCLUDE_UID,
                                                     RULE_MATCH_USERID,
                                                     RULE_EXCLUDE_USERID,
                                                     RULE_MATCH_AUDIO_SESSION_ID,
                                                     RULE_EXCLUDE_AUDIO_SESSION_ID};

// Generates a random string.
std::string CreateRandomString(size_t n) {
    std::string data =
            "abcdefghijklmnopqrstuvwxyz"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "0123456789";
    srand(static_cast<unsigned int>(time(0)));
    std::string s(n, ' ');
    for (size_t i = 0; i < n; ++i) {
        s[i] = data[rand() % data.size()];
    }
    return s;
}

class FillAudioAttributes {
  public:
    void fillAudioAttributes(audio_attributes_t& attr);

    unsigned int mSeed;
};

void FillAudioAttributes::fillAudioAttributes(audio_attributes_t& attr) {
    attr.content_type = kContentType[rand() % kContentType.size()];
    attr.usage = kUsages[rand() % kUsages.size()];
    attr.source = kInputSources[rand() % kInputSources.size()];
    // attr.flags -> [0, (1 << (CAPTURE_PRIVATE + 1) - 1)]
    attr.flags = static_cast<audio_flags_mask_t>(rand() & 0x3ffd);  // exclude AUDIO_FLAG_SECURE
    sprintf(attr.tags, "%s",
            CreateRandomString((int)rand() % (AUDIO_ATTRIBUTES_TAGS_MAX_SIZE - 1)).c_str());
}

class SerializationTest : public FillAudioAttributes, public ::testing::Test {
    void SetUp() override {
        mSeed = static_cast<unsigned int>(time(0));
        srand(mSeed);
    }
};

// UNIT TESTS
TEST_F(SerializationTest, AudioProductStrategyBinderization) {
    for (int j = 0; j < 512; j++) {
        const std::string name{"Test APSBinderization for seed::" + std::to_string(mSeed)};
        SCOPED_TRACE(name);
        std::vector<VolumeGroupAttributes> volumeGroupAttrVector;
        for (auto i = 0; i < 16; i++) {
            audio_attributes_t attributes;
            fillAudioAttributes(attributes);
            VolumeGroupAttributes volumeGroupAttr{static_cast<volume_group_t>(rand()),
                                                  kStreamtypes[rand() % kStreamtypes.size()],
                                                  attributes};
            volumeGroupAttrVector.push_back(volumeGroupAttr);
        }
        product_strategy_t psId = static_cast<product_strategy_t>(rand());
        AudioProductStrategy aps{name, volumeGroupAttrVector, psId};

        Parcel p;
        EXPECT_EQ(NO_ERROR, aps.writeToParcel(&p));

        AudioProductStrategy apsCopy;
        p.setDataPosition(0);
        EXPECT_EQ(NO_ERROR, apsCopy.readFromParcel(&p));
        EXPECT_EQ(apsCopy.getName(), name);
        EXPECT_EQ(apsCopy.getId(), psId);
        auto avec = apsCopy.getVolumeGroupAttributes();
        EXPECT_EQ(avec.size(), volumeGroupAttrVector.size());
        for (int i = 0; i < std::min(avec.size(), volumeGroupAttrVector.size()); i++) {
            EXPECT_EQ(avec[i].getGroupId(), volumeGroupAttrVector[i].getGroupId());
            EXPECT_EQ(avec[i].getStreamType(), volumeGroupAttrVector[i].getStreamType());
            EXPECT_TRUE(avec[i].getAttributes() == volumeGroupAttrVector[i].getAttributes());
        }
    }
}

TEST_F(SerializationTest, AudioVolumeGroupBinderization) {
    for (int j = 0; j < 512; j++) {
        const std::string name{"Test AVGBinderization for seed::" + std::to_string(mSeed)};
        volume_group_t groupId = static_cast<volume_group_t>(rand());
        std::vector<audio_attributes_t> attributesvector;
        for (auto i = 0; i < 16; i++) {
            audio_attributes_t attributes;
            fillAudioAttributes(attributes);
            attributesvector.push_back(attributes);
        }
        std::vector<audio_stream_type_t> streamsvector;
        for (auto i = 0; i < 8; i++) {
            streamsvector.push_back(kStreamtypes[rand() % kStreamtypes.size()]);
        }
        AudioVolumeGroup avg{name, groupId, attributesvector, streamsvector};

        Parcel p;
        EXPECT_EQ(NO_ERROR, avg.writeToParcel(&p));

        AudioVolumeGroup avgCopy;
        p.setDataPosition(0);
        EXPECT_EQ(NO_ERROR, avgCopy.readFromParcel(&p)) << name;
        EXPECT_EQ(avgCopy.getName(), name) << name;
        EXPECT_EQ(avgCopy.getId(), groupId) << name;
        auto avec = avgCopy.getAudioAttributes();
        EXPECT_EQ(avec.size(), attributesvector.size()) << name;
        for (int i = 0; i < avec.size(); i++) {
            EXPECT_TRUE(avec[i] == attributesvector[i]) << name;
        }
        StreamTypeVector svec = avgCopy.getStreamTypes();
        EXPECT_EQ(svec.size(), streamsvector.size()) << name;
        for (int i = 0; i < svec.size(); i++) {
            EXPECT_EQ(svec[i], streamsvector[i]) << name;
        }
    }
}

TEST_F(SerializationTest, AudioMixBinderization) {
    for (int j = 0; j < 512; j++) {
        const std::string msg{"Test AMBinderization for seed::" + std::to_string(mSeed)};
        std::vector<AudioMixMatchCriterion> criteria;
        criteria.reserve(16);
        for (int i = 0; i < 16; i++) {
            AudioMixMatchCriterion ammc{kUsages[rand() % kUsages.size()],
                                        kInputSources[rand() % kInputSources.size()],
                                        kMixMatchRules[rand() % kMixMatchRules.size()]};
            criteria.push_back(ammc);
        }
        audio_config_t config{};
        config.sample_rate = 48000;
        config.channel_mask = AUDIO_CHANNEL_IN_MONO;
        config.format = AUDIO_FORMAT_PCM_16_BIT;
        config.offload_info = AUDIO_INFO_INITIALIZER;
        config.frame_count = 4800;
        AudioMix am{criteria,
                    static_cast<uint32_t>(rand()),
                    config,
                    static_cast<uint32_t>(rand()),
                    String8(msg.c_str()),
                    static_cast<uint32_t>(rand())};

        Parcel p;
        EXPECT_EQ(NO_ERROR, am.writeToParcel(&p)) << msg;

        AudioMix amCopy;
        p.setDataPosition(0);
        EXPECT_EQ(NO_ERROR, amCopy.readFromParcel(&p)) << msg;
        EXPECT_EQ(amCopy.mMixType, am.mMixType) << msg;
        EXPECT_EQ(amCopy.mFormat.sample_rate, am.mFormat.sample_rate) << msg;
        EXPECT_EQ(amCopy.mFormat.channel_mask, am.mFormat.channel_mask) << msg;
        EXPECT_EQ(amCopy.mFormat.format, am.mFormat.format) << msg;
        EXPECT_EQ(amCopy.mRouteFlags, am.mRouteFlags) << msg;
        EXPECT_EQ(amCopy.mDeviceAddress, am.mDeviceAddress) << msg;
        EXPECT_EQ(amCopy.mCbFlags, am.mCbFlags) << msg;
        EXPECT_EQ(amCopy.mCriteria.size(), am.mCriteria.size()) << msg;
        for (auto i = 0; i < amCopy.mCriteria.size(); i++) {
            EXPECT_EQ(amCopy.mCriteria[i].mRule, am.mCriteria[i].mRule) << msg;
            EXPECT_EQ(amCopy.mCriteria[i].mValue.mUserId, am.mCriteria[i].mValue.mUserId) << msg;
        }
    }
}

using MMCTestParams = std::tuple<audio_usage_t, audio_source_t, uint32_t>;

class MMCParameterizedTest : public FillAudioAttributes,
                             public ::testing::TestWithParam<MMCTestParams> {
  public:
    MMCParameterizedTest()
        : mAudioUsage(std::get<0>(GetParam())),
          mAudioSource(std::get<1>(GetParam())),
          mAudioMixMatchRules(std::get<2>(GetParam())){};

    const audio_usage_t mAudioUsage;
    const audio_source_t mAudioSource;
    const uint32_t mAudioMixMatchRules;

    void SetUp() override {
        mSeed = static_cast<unsigned int>(time(0));
        srand(mSeed);
    }
};

TEST_P(MMCParameterizedTest, AudioMixMatchCriterionBinderization) {
    const std::string msg{"Test AMMCBinderization for seed::" + std::to_string(mSeed)};
    AudioMixMatchCriterion ammc{mAudioUsage, mAudioSource, mAudioMixMatchRules};

    Parcel p;
    EXPECT_EQ(NO_ERROR, ammc.writeToParcel(&p)) << msg;

    AudioMixMatchCriterion ammcCopy;
    p.setDataPosition(0);
    EXPECT_EQ(NO_ERROR, ammcCopy.readFromParcel(&p)) << msg;
    EXPECT_EQ(ammcCopy.mRule, ammc.mRule) << msg;
    EXPECT_EQ(ammcCopy.mValue.mUserId, ammc.mValue.mUserId) << msg;
}

// audioUsage, audioSource, audioMixMatchRules
INSTANTIATE_TEST_SUITE_P(SerializationParameterizedTests, MMCParameterizedTest,
                         ::testing::Combine(testing::ValuesIn(kUsages),
                                            testing::ValuesIn(kInputSources),
                                            testing::ValuesIn(kMixMatchRules)));

using AudioAttributesTestParams = std::tuple<audio_stream_type_t>;

class AudioAttributesParameterizedTest
    : public FillAudioAttributes,
      public ::testing::TestWithParam<AudioAttributesTestParams> {
  public:
    AudioAttributesParameterizedTest() : mAudioStream(std::get<0>(GetParam())){};

    const audio_stream_type_t mAudioStream;

    void SetUp() override {
        mSeed = static_cast<unsigned int>(time(0));
        srand(mSeed);
    }
};

TEST_P(AudioAttributesParameterizedTest, AudioAttributesBinderization) {
    const std::string msg{"Test AABinderization for seed::" + std::to_string(mSeed)};
    volume_group_t groupId = static_cast<volume_group_t>(rand());
    audio_stream_type_t stream = mAudioStream;
    audio_attributes_t attributes;
    fillAudioAttributes(attributes);
    VolumeGroupAttributes volumeGroupAttr{groupId, stream, attributes};

    Parcel p;
    EXPECT_EQ(NO_ERROR, volumeGroupAttr.writeToParcel(&p)) << msg;

    VolumeGroupAttributes volumeGroupAttrCopy;
    p.setDataPosition(0);
    EXPECT_EQ(NO_ERROR, volumeGroupAttrCopy.readFromParcel(&p)) << msg;
    EXPECT_EQ(volumeGroupAttrCopy.getGroupId(), volumeGroupAttr.getGroupId()) << msg;
    EXPECT_EQ(volumeGroupAttrCopy.getStreamType(), volumeGroupAttr.getStreamType()) << msg;
    EXPECT_TRUE(volumeGroupAttrCopy.getAttributes() == attributes) << msg;
}

// audioStream
INSTANTIATE_TEST_SUITE_P(SerializationParameterizedTests, AudioAttributesParameterizedTest,
                         ::testing::Combine(testing::ValuesIn(kStreamtypes)));

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    ::testing::UnitTest::GetInstance()->listeners().Append(new TestExecutionTracer());
    return RUN_ALL_TESTS();
}
