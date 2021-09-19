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

#include <gtest/gtest.h>

#include <media/AudioCommonTypes.h>
#include <media/AidlConversion.h>

using namespace android;
using namespace android::aidl_utils;

using media::audio::common::AudioChannelLayout;
using media::audio::common::AudioDeviceDescription;
using media::audio::common::AudioDeviceType;
using media::audio::common::AudioFormatDescription;
using media::audio::common::AudioFormatType;
using media::audio::common::PcmType;

namespace {

template<typename T> size_t hash(const T& t) {
    return std::hash<T>{}(t);
}

AudioChannelLayout make_ACL_None() {
    return AudioChannelLayout{};
}

AudioChannelLayout make_ACL_Invalid() {
    return AudioChannelLayout::make<AudioChannelLayout::Tag::invalid>(0);
}

AudioChannelLayout make_ACL_Stereo() {
    return AudioChannelLayout::make<AudioChannelLayout::Tag::layoutMask>(
            AudioChannelLayout::LAYOUT_STEREO);
}

AudioChannelLayout make_ACL_ChannelIndex2() {
    return AudioChannelLayout::make<AudioChannelLayout::Tag::indexMask>(
            AudioChannelLayout::INDEX_MASK_2);
}

AudioChannelLayout make_ACL_ChannelIndexArbitrary() {
    // Use channels 1 and 3.
    return AudioChannelLayout::make<AudioChannelLayout::Tag::indexMask>(5);
}

AudioChannelLayout make_ACL_VoiceCall() {
    return AudioChannelLayout::make<AudioChannelLayout::Tag::voiceMask>(
            AudioChannelLayout::VOICE_CALL_MONO);
}

AudioDeviceDescription make_AudioDeviceDescription(AudioDeviceType type,
        const std::string& connection = "") {
    AudioDeviceDescription result;
    result.type = type;
    result.connection = connection;
    return result;
}

AudioDeviceDescription make_ADD_None() {
    return AudioDeviceDescription{};
}

AudioDeviceDescription make_ADD_DefaultIn() {
    return make_AudioDeviceDescription(AudioDeviceType::IN_DEFAULT);
}

AudioDeviceDescription make_ADD_DefaultOut() {
    return make_AudioDeviceDescription(AudioDeviceType::OUT_DEFAULT);
}

AudioDeviceDescription make_ADD_WiredHeadset() {
    return make_AudioDeviceDescription(AudioDeviceType::OUT_HEADSET,
            AudioDeviceDescription::CONNECTION_ANALOG());
}

AudioDeviceDescription make_ADD_BtScoHeadset() {
    return make_AudioDeviceDescription(AudioDeviceType::OUT_HEADSET,
            AudioDeviceDescription::CONNECTION_BT_SCO());
}

AudioFormatDescription make_AudioFormatDescription(AudioFormatType type) {
    AudioFormatDescription result;
    result.type = type;
    return result;
}

AudioFormatDescription make_AudioFormatDescription(PcmType pcm) {
    auto result = make_AudioFormatDescription(AudioFormatType::PCM);
    result.pcm = pcm;
    return result;
}

AudioFormatDescription make_AudioFormatDescription(const std::string& encoding) {
    AudioFormatDescription result;
    result.encoding = encoding;
    return result;
}

AudioFormatDescription make_AudioFormatDescription(PcmType transport,
        const std::string& encoding) {
    auto result = make_AudioFormatDescription(encoding);
    result.pcm = transport;
    return result;
}

AudioFormatDescription make_AFD_Default() {
    return AudioFormatDescription{};
}

AudioFormatDescription make_AFD_Invalid() {
    return make_AudioFormatDescription(AudioFormatType::SYS_RESERVED_INVALID);
}

AudioFormatDescription make_AFD_Pcm16Bit() {
    return make_AudioFormatDescription(PcmType::INT_16_BIT);
}

AudioFormatDescription make_AFD_Bitstream() {
    return make_AudioFormatDescription("example");
}

AudioFormatDescription make_AFD_Encap() {
    return make_AudioFormatDescription(PcmType::INT_16_BIT, "example.encap");
}

AudioFormatDescription make_AFD_Encap_with_Enc() {
    auto afd = make_AFD_Encap();
    afd.encoding += "+example";
    return afd;
}

}  // namespace

// Verify that two independently constructed ADDs/AFDs have the same hash.
// This ensures that regardless of whether the ADD/AFD instance originates
// from, it can be correctly compared to other ADD/AFD instance. Thus,
// for example, a 16-bit integer format description provided by HAL
// is identical to the same format description constructed by the framework.
class HashIdentityTest : public ::testing::Test {
  public:
    template<typename T> void verifyHashIdentity(const std::vector<std::function<T()>>& valueGens) {
        for (size_t i = 0; i < valueGens.size(); ++i) {
            for (size_t j = 0; j < valueGens.size(); ++j) {
                if (i == j) {
                    EXPECT_EQ(hash(valueGens[i]()), hash(valueGens[i]())) << i;
                } else {
                    EXPECT_NE(hash(valueGens[i]()), hash(valueGens[j]())) << i << ", " << j;
                }
            }
        }
    }
};

TEST_F(HashIdentityTest, AudioChannelLayoutHashIdentity) {
    verifyHashIdentity<AudioChannelLayout>({
            make_ACL_None, make_ACL_Invalid, make_ACL_Stereo, make_ACL_ChannelIndex2,
            make_ACL_ChannelIndexArbitrary, make_ACL_VoiceCall});
}

TEST_F(HashIdentityTest, AudioDeviceDescriptionHashIdentity) {
    verifyHashIdentity<AudioDeviceDescription>({
            make_ADD_None, make_ADD_DefaultIn, make_ADD_DefaultOut, make_ADD_WiredHeadset,
            make_ADD_BtScoHeadset});
}

TEST_F(HashIdentityTest, AudioFormatDescriptionHashIdentity) {
    verifyHashIdentity<AudioFormatDescription>({
            make_AFD_Default, make_AFD_Invalid, make_AFD_Pcm16Bit, make_AFD_Bitstream,
            make_AFD_Encap, make_AFD_Encap_with_Enc});
}

using ChannelLayoutParam = std::tuple<AudioChannelLayout, bool /*isInput*/>;
class AudioChannelLayoutRoundTripTest :
        public testing::TestWithParam<ChannelLayoutParam> {};
TEST_P(AudioChannelLayoutRoundTripTest, Aidl2Legacy2Aidl) {
    const auto initial = std::get<0>(GetParam());
    const bool isInput = std::get<1>(GetParam());
    auto conv = aidl2legacy_AudioChannelLayout_audio_channel_mask_t(initial, isInput);
    ASSERT_TRUE(conv.ok());
    auto convBack = legacy2aidl_audio_channel_mask_t_AudioChannelLayout(conv.value(), isInput);
    ASSERT_TRUE(convBack.ok());
    EXPECT_EQ(initial, convBack.value());
}
INSTANTIATE_TEST_SUITE_P(AudioChannelLayoutRoundTrip,
        AudioChannelLayoutRoundTripTest,
        testing::Combine(
                testing::Values(AudioChannelLayout{}, make_ACL_Invalid(), make_ACL_Stereo(),
                        make_ACL_ChannelIndex2(), make_ACL_ChannelIndexArbitrary()),
                testing::Values(false, true)));
INSTANTIATE_TEST_SUITE_P(AudioChannelVoiceRoundTrip,
        AudioChannelLayoutRoundTripTest,
        // In legacy constants the voice call is only defined for input.
        testing::Combine(testing::Values(make_ACL_VoiceCall()), testing::Values(true)));

class AudioDeviceDescriptionRoundTripTest :
        public testing::TestWithParam<AudioDeviceDescription> {};
TEST_P(AudioDeviceDescriptionRoundTripTest, Aidl2Legacy2Aidl) {
    const auto initial = GetParam();
    auto conv = aidl2legacy_AudioDeviceDescription_audio_devices_t(initial);
    ASSERT_TRUE(conv.ok());
    auto convBack = legacy2aidl_audio_devices_t_AudioDeviceDescription(conv.value());
    ASSERT_TRUE(convBack.ok());
    EXPECT_EQ(initial, convBack.value());
}
INSTANTIATE_TEST_SUITE_P(AudioDeviceDescriptionRoundTrip,
        AudioDeviceDescriptionRoundTripTest,
        testing::Values(AudioDeviceDescription{}, make_ADD_DefaultIn(),
                make_ADD_DefaultOut(), make_ADD_WiredHeadset(), make_ADD_BtScoHeadset()));

class AudioFormatDescriptionRoundTripTest :
        public testing::TestWithParam<AudioFormatDescription> {};
TEST_P(AudioFormatDescriptionRoundTripTest, Aidl2Legacy2Aidl) {
    const auto initial = GetParam();
    auto conv = aidl2legacy_AudioFormatDescription_audio_format_t(initial);
    ASSERT_TRUE(conv.ok());
    auto convBack = legacy2aidl_audio_format_t_AudioFormatDescription(conv.value());
    ASSERT_TRUE(convBack.ok());
    EXPECT_EQ(initial, convBack.value());
}
INSTANTIATE_TEST_SUITE_P(AudioFormatDescriptionRoundTrip,
        AudioFormatDescriptionRoundTripTest,
        testing::Values(make_AFD_Invalid(), AudioFormatDescription{}, make_AFD_Pcm16Bit()));
