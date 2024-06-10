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

#include <iostream>
#include <string>

#include <gtest/gtest.h>

#include <media/AidlConversion.h>
#include <media/AudioCommonTypes.h>

using namespace android;
using namespace android::aidl_utils;

using media::AudioDirectMode;
using media::AudioPortConfigFw;
using media::AudioPortDeviceExtSys;
using media::AudioPortFw;
using media::AudioPortRole;
using media::AudioPortType;
using media::audio::common::AudioChannelLayout;
using media::audio::common::AudioDevice;
using media::audio::common::AudioDeviceAddress;
using media::audio::common::AudioDeviceDescription;
using media::audio::common::AudioDeviceType;
using media::audio::common::AudioEncapsulationMetadataType;
using media::audio::common::AudioEncapsulationType;
using media::audio::common::AudioFormatDescription;
using media::audio::common::AudioFormatType;
using media::audio::common::AudioGain;
using media::audio::common::AudioGainConfig;
using media::audio::common::AudioGainMode;
using media::audio::common::AudioInputFlags;
using media::audio::common::AudioIoFlags;
using media::audio::common::AudioOutputFlags;
using media::audio::common::AudioPortDeviceExt;
using media::audio::common::AudioProfile;
using media::audio::common::AudioStandard;
using media::audio::common::ExtraAudioDescriptor;
using media::audio::common::Int;
using media::audio::common::MicrophoneDynamicInfo;
using media::audio::common::MicrophoneInfo;
using media::audio::common::PcmType;

// Provide value printers for types generated from AIDL
// They need to be in the same namespace as the types we intend to print
namespace android::media {
#define DEFINE_PRINTING_TEMPLATES()                                                               \
    template <typename P>                                                                         \
    std::enable_if_t<std::is_base_of_v<::android::Parcelable, P>, std::ostream&> operator<<(      \
            std::ostream& os, const P& p) {                                                       \
        return os << p.toString();                                                                \
    }                                                                                             \
    template <typename E>                                                                         \
    std::enable_if_t<std::is_enum_v<E>, std::ostream&> operator<<(std::ostream& os, const E& e) { \
        return os << toString(e);                                                                 \
    }
DEFINE_PRINTING_TEMPLATES();

namespace audio::common {
DEFINE_PRINTING_TEMPLATES();
}  // namespace audio::common
#undef DEFINE_PRINTING_TEMPLATES
}  // namespace android::media

namespace {

template <typename T>
size_t hash(const T& t) {
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

AudioChannelLayout make_ACL_Tri() {
    return AudioChannelLayout::make<AudioChannelLayout::Tag::layoutMask>(
            AudioChannelLayout::LAYOUT_TRI);
}

AudioChannelLayout make_ACL_LayoutArbitrary() {
    return AudioChannelLayout::make<AudioChannelLayout::Tag::layoutMask>(
            // Use channels that exist both for input and output,
            // but doesn't form a known layout mask.
            AudioChannelLayout::CHANNEL_FRONT_LEFT | AudioChannelLayout::CHANNEL_FRONT_RIGHT |
            AudioChannelLayout::CHANNEL_TOP_SIDE_LEFT | AudioChannelLayout::CHANNEL_TOP_SIDE_RIGHT);
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

AudioDeviceDescription make_ADD_MicIn() {
    return make_AudioDeviceDescription(AudioDeviceType::IN_MICROPHONE);
}

AudioDeviceDescription make_ADD_RSubmixIn() {
    return make_AudioDeviceDescription(AudioDeviceType::IN_SUBMIX,
                                       AudioDeviceDescription::CONNECTION_VIRTUAL());
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

AudioDeviceDescription make_ADD_BtA2dpHeadphone() {
    return make_AudioDeviceDescription(AudioDeviceType::OUT_HEADPHONE,
                                       AudioDeviceDescription::CONNECTION_BT_A2DP());
}

AudioDeviceDescription make_ADD_BtLeHeadset() {
    return make_AudioDeviceDescription(AudioDeviceType::OUT_HEADSET,
                                       AudioDeviceDescription::CONNECTION_BT_LE());
}

AudioDeviceDescription make_ADD_BtLeBroadcast() {
    return make_AudioDeviceDescription(AudioDeviceType::OUT_BROADCAST,
                                       AudioDeviceDescription::CONNECTION_BT_LE());
}

AudioDeviceDescription make_ADD_IpV4Device() {
    return make_AudioDeviceDescription(AudioDeviceType::OUT_DEVICE,
                                       AudioDeviceDescription::CONNECTION_IP_V4());
}

AudioDeviceDescription make_ADD_UsbHeadset() {
    return make_AudioDeviceDescription(AudioDeviceType::OUT_HEADSET,
                                       AudioDeviceDescription::CONNECTION_USB());
}

AudioDevice make_AudioDevice(const AudioDeviceDescription& type,
                             const AudioDeviceAddress& address) {
    AudioDevice result;
    result.type = type;
    result.address = address;
    return result;
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

AudioFormatDescription make_AudioFormatDescription(PcmType transport, const std::string& encoding) {
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

android::media::TrackSecondaryOutputInfo make_TrackSecondaryOutputInfo() {
    android::media::TrackSecondaryOutputInfo result;
    result.portId = 1;
    result.secondaryOutputIds = {0, 5, 7};
    return result;
}

ExtraAudioDescriptor make_ExtraAudioDescriptor(AudioStandard audioStandard,
                                               AudioEncapsulationType audioEncapsulationType) {
    ExtraAudioDescriptor result;
    result.standard = audioStandard;
    result.audioDescriptor = {0xb4, 0xaf, 0x98, 0x1a};
    result.encapsulationType = audioEncapsulationType;
    return result;
}

}  // namespace

// Verify that two independently constructed ADDs/AFDs have the same hash.
// This ensures that regardless of whether the ADD/AFD instance originates
// from, it can be correctly compared to other ADD/AFD instance. Thus,
// for example, a 16-bit integer format description provided by HAL
// is identical to the same format description constructed by the framework.
class HashIdentityTest : public ::testing::Test {
  public:
    template <typename T>
    void verifyHashIdentity(const std::vector<std::function<T()>>& valueGens) {
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
    verifyHashIdentity<AudioChannelLayout>({make_ACL_None, make_ACL_Invalid, make_ACL_Stereo,
                                            make_ACL_LayoutArbitrary, make_ACL_ChannelIndex2,
                                            make_ACL_ChannelIndexArbitrary, make_ACL_VoiceCall});
}

TEST_F(HashIdentityTest, AudioDeviceDescriptionHashIdentity) {
    verifyHashIdentity<AudioDeviceDescription>({make_ADD_None, make_ADD_DefaultIn,
                                                make_ADD_DefaultOut, make_ADD_WiredHeadset,
                                                make_ADD_BtScoHeadset});
}

TEST_F(HashIdentityTest, AudioFormatDescriptionHashIdentity) {
    verifyHashIdentity<AudioFormatDescription>({make_AFD_Default, make_AFD_Invalid,
                                                make_AFD_Pcm16Bit, make_AFD_Bitstream,
                                                make_AFD_Encap, make_AFD_Encap_with_Enc});
}

using ChannelLayoutParam = std::tuple<AudioChannelLayout, bool /*isInput*/>;
class AudioChannelLayoutRoundTripTest : public testing::TestWithParam<ChannelLayoutParam> {};
TEST_P(AudioChannelLayoutRoundTripTest, Aidl2Legacy2Aidl) {
    const auto initial = std::get<0>(GetParam());
    const bool isInput = std::get<1>(GetParam());
    auto conv = aidl2legacy_AudioChannelLayout_audio_channel_mask_t(initial, isInput);
    ASSERT_TRUE(conv.ok());
    auto convBack = legacy2aidl_audio_channel_mask_t_AudioChannelLayout(conv.value(), isInput);
    ASSERT_TRUE(convBack.ok());
    EXPECT_EQ(initial, convBack.value());
}

INSTANTIATE_TEST_SUITE_P(
        AudioChannelLayoutRoundTrip, AudioChannelLayoutRoundTripTest,
        testing::Combine(
                testing::Values(AudioChannelLayout{}, make_ACL_Invalid(), make_ACL_Stereo(),
                                make_ACL_Tri(), make_ACL_LayoutArbitrary(),
                                make_ACL_ChannelIndex2(), make_ACL_ChannelIndexArbitrary(),
                                AudioChannelLayout::make<AudioChannelLayout::Tag::layoutMask>(
                                        AudioChannelLayout::CHANNEL_FRONT_LEFT),
                                AudioChannelLayout::make<AudioChannelLayout::Tag::layoutMask>(
                                        AudioChannelLayout::CHANNEL_FRONT_RIGHT),
                                AudioChannelLayout::make<AudioChannelLayout::Tag::layoutMask>(
                                        AudioChannelLayout::CHANNEL_BACK_CENTER),
                                AudioChannelLayout::make<AudioChannelLayout::Tag::layoutMask>(
                                        AudioChannelLayout::CHANNEL_BACK_LEFT),
                                AudioChannelLayout::make<AudioChannelLayout::Tag::layoutMask>(
                                        AudioChannelLayout::CHANNEL_BACK_RIGHT),
                                AudioChannelLayout::make<AudioChannelLayout::Tag::layoutMask>(
                                        AudioChannelLayout::CHANNEL_FRONT_CENTER),
                                AudioChannelLayout::make<AudioChannelLayout::Tag::layoutMask>(
                                        AudioChannelLayout::CHANNEL_LOW_FREQUENCY),
                                AudioChannelLayout::make<AudioChannelLayout::Tag::layoutMask>(
                                        AudioChannelLayout::CHANNEL_TOP_SIDE_LEFT),
                                AudioChannelLayout::make<AudioChannelLayout::Tag::layoutMask>(
                                        AudioChannelLayout::CHANNEL_TOP_SIDE_RIGHT)),
                testing::Values(false, true)));
INSTANTIATE_TEST_SUITE_P(AudioChannelVoiceRoundTrip, AudioChannelLayoutRoundTripTest,
                         // In legacy constants the voice call is only defined for input.
                         testing::Combine(testing::Values(make_ACL_VoiceCall()),
                                          testing::Values(true)));

INSTANTIATE_TEST_SUITE_P(
        OutAudioChannelLayoutLayoutRoundTrip, AudioChannelLayoutRoundTripTest,
        testing::Combine(
                testing::Values(AudioChannelLayout::make<AudioChannelLayout::Tag::layoutMask>(
                                        AudioChannelLayout::CHANNEL_FRONT_LEFT_OF_CENTER),
                                AudioChannelLayout::make<AudioChannelLayout::Tag::layoutMask>(
                                        AudioChannelLayout::CHANNEL_FRONT_RIGHT_OF_CENTER),
                                AudioChannelLayout::make<AudioChannelLayout::Tag::layoutMask>(
                                        AudioChannelLayout::CHANNEL_SIDE_LEFT),
                                AudioChannelLayout::make<AudioChannelLayout::Tag::layoutMask>(
                                        AudioChannelLayout::CHANNEL_SIDE_RIGHT),
                                AudioChannelLayout::make<AudioChannelLayout::Tag::layoutMask>(
                                        AudioChannelLayout::CHANNEL_TOP_CENTER),
                                AudioChannelLayout::make<AudioChannelLayout::Tag::layoutMask>(
                                        AudioChannelLayout::CHANNEL_TOP_FRONT_LEFT),
                                AudioChannelLayout::make<AudioChannelLayout::Tag::layoutMask>(
                                        AudioChannelLayout::CHANNEL_TOP_FRONT_CENTER),
                                AudioChannelLayout::make<AudioChannelLayout::Tag::layoutMask>(
                                        AudioChannelLayout::CHANNEL_TOP_FRONT_RIGHT),
                                AudioChannelLayout::make<AudioChannelLayout::Tag::layoutMask>(
                                        AudioChannelLayout::CHANNEL_TOP_BACK_LEFT),
                                AudioChannelLayout::make<AudioChannelLayout::Tag::layoutMask>(
                                        AudioChannelLayout::CHANNEL_TOP_BACK_CENTER),
                                AudioChannelLayout::make<AudioChannelLayout::Tag::layoutMask>(
                                        AudioChannelLayout::CHANNEL_TOP_BACK_RIGHT),
                                AudioChannelLayout::make<AudioChannelLayout::Tag::layoutMask>(
                                        AudioChannelLayout::CHANNEL_BOTTOM_FRONT_LEFT),
                                AudioChannelLayout::make<AudioChannelLayout::Tag::layoutMask>(
                                        AudioChannelLayout::CHANNEL_BOTTOM_FRONT_CENTER),
                                AudioChannelLayout::make<AudioChannelLayout::Tag::layoutMask>(
                                        AudioChannelLayout::CHANNEL_BOTTOM_FRONT_RIGHT),
                                AudioChannelLayout::make<AudioChannelLayout::Tag::layoutMask>(
                                        AudioChannelLayout::CHANNEL_LOW_FREQUENCY_2),
                                AudioChannelLayout::make<AudioChannelLayout::Tag::layoutMask>(
                                        AudioChannelLayout::CHANNEL_FRONT_WIDE_LEFT),
                                AudioChannelLayout::make<AudioChannelLayout::Tag::layoutMask>(
                                        AudioChannelLayout::CHANNEL_FRONT_WIDE_RIGHT),
                                AudioChannelLayout::make<AudioChannelLayout::Tag::layoutMask>(
                                        AudioChannelLayout::CHANNEL_HAPTIC_A),
                                AudioChannelLayout::make<AudioChannelLayout::Tag::layoutMask>(
                                        AudioChannelLayout::CHANNEL_HAPTIC_B)),
                testing::Values(false)));

using ChannelLayoutEdgeCaseParam = std::tuple<int /*legacy*/, bool /*isInput*/, bool /*isValid*/>;
class AudioChannelLayoutEdgeCaseTest : public testing::TestWithParam<ChannelLayoutEdgeCaseParam> {};
TEST_P(AudioChannelLayoutEdgeCaseTest, Legacy2Aidl) {
    const audio_channel_mask_t legacy = static_cast<audio_channel_mask_t>(std::get<0>(GetParam()));
    const bool isInput = std::get<1>(GetParam());
    const bool isValid = std::get<2>(GetParam());
    auto conv = legacy2aidl_audio_channel_mask_t_AudioChannelLayout(legacy, isInput);
    EXPECT_EQ(isValid, conv.ok());
}
INSTANTIATE_TEST_SUITE_P(
        AudioChannelLayoutEdgeCase, AudioChannelLayoutEdgeCaseTest,
        testing::Values(
                // Valid legacy input masks.
                std::make_tuple(AUDIO_CHANNEL_IN_VOICE_UPLINK_MONO, true, true),
                std::make_tuple(AUDIO_CHANNEL_IN_VOICE_DNLINK_MONO, true, true),
                std::make_tuple(AUDIO_CHANNEL_IN_VOICE_CALL_MONO, true, true),
                // Valid legacy output masks.
                std::make_tuple(
                        // This has the same numerical representation as Mask 'A' below
                        AUDIO_CHANNEL_OUT_FRONT_CENTER | AUDIO_CHANNEL_OUT_LOW_FREQUENCY |
                                AUDIO_CHANNEL_OUT_TOP_FRONT_RIGHT,
                        false, true),
                std::make_tuple(
                        // This has the same numerical representation as Mask 'B' below
                        AUDIO_CHANNEL_OUT_FRONT_CENTER | AUDIO_CHANNEL_OUT_LOW_FREQUENCY |
                                AUDIO_CHANNEL_OUT_TOP_BACK_LEFT,
                        false, true),
                // Invalid legacy input masks.
                std::make_tuple(AUDIO_CHANNEL_IN_6, true, false),
                std::make_tuple(AUDIO_CHANNEL_IN_6 | AUDIO_CHANNEL_IN_FRONT_PROCESSED, true, false),
                std::make_tuple(AUDIO_CHANNEL_IN_PRESSURE | AUDIO_CHANNEL_IN_X_AXIS |
                                        AUDIO_CHANNEL_IN_Y_AXIS | AUDIO_CHANNEL_IN_Z_AXIS,
                                true, false),
                std::make_tuple(  // Mask 'A'
                        AUDIO_CHANNEL_IN_STEREO | AUDIO_CHANNEL_IN_VOICE_UPLINK, true, false),
                std::make_tuple(  // Mask 'B'
                        AUDIO_CHANNEL_IN_STEREO | AUDIO_CHANNEL_IN_VOICE_DNLINK, true, false)));

class AudioDeviceDescriptionRoundTripTest : public testing::TestWithParam<AudioDeviceDescription> {
};
TEST_P(AudioDeviceDescriptionRoundTripTest, Aidl2Legacy2Aidl) {
    const auto initial = GetParam();
    auto conv = aidl2legacy_AudioDeviceDescription_audio_devices_t(initial);
    ASSERT_TRUE(conv.ok());
    auto convBack = legacy2aidl_audio_devices_t_AudioDeviceDescription(conv.value());
    ASSERT_TRUE(convBack.ok());
    EXPECT_EQ(initial, convBack.value());
}
INSTANTIATE_TEST_SUITE_P(AudioDeviceDescriptionRoundTrip, AudioDeviceDescriptionRoundTripTest,
                         testing::Values(AudioDeviceDescription{}, make_ADD_DefaultIn(),
                                         make_ADD_DefaultOut(), make_ADD_WiredHeadset(),
                                         make_ADD_BtScoHeadset()));

class AudioDeviceRoundTripTest : public testing::TestWithParam<AudioDevice> {};
TEST_P(AudioDeviceRoundTripTest, Aidl2Legacy2Aidl) {
    const auto initial = GetParam();
    audio_devices_t legacyType;
    String8 legacyAddress;
    status_t status = aidl2legacy_AudioDevice_audio_device(initial, &legacyType, &legacyAddress);
    ASSERT_EQ(OK, status);
    auto convBack = legacy2aidl_audio_device_AudioDevice(legacyType, legacyAddress);
    ASSERT_TRUE(convBack.ok());
    EXPECT_EQ(initial, convBack.value());
}
INSTANTIATE_TEST_SUITE_P(
        AudioDeviceRoundTrip, AudioDeviceRoundTripTest,
        testing::Values(
                make_AudioDevice(make_ADD_MicIn(),
                                 AudioDeviceAddress::make<AudioDeviceAddress::Tag::id>("bottom")),
                make_AudioDevice(make_ADD_RSubmixIn(),
                                 AudioDeviceAddress::make<AudioDeviceAddress::Tag::id>("1:2-in-3")),
                // The case of a "blueprint" device port for an external device.
                make_AudioDevice(make_ADD_BtScoHeadset(),
                                 AudioDeviceAddress::make<AudioDeviceAddress::Tag::id>("")),
                make_AudioDevice(make_ADD_BtScoHeadset(),
                                 AudioDeviceAddress::make<AudioDeviceAddress::Tag::mac>(
                                         std::vector<uint8_t>{1, 2, 3, 4, 5, 6})),
                // Another "blueprint"
                make_AudioDevice(make_ADD_BtA2dpHeadphone(),
                                 AudioDeviceAddress::make<AudioDeviceAddress::Tag::id>("")),
                make_AudioDevice(make_ADD_BtA2dpHeadphone(),
                                 AudioDeviceAddress::make<AudioDeviceAddress::Tag::mac>(
                                         std::vector<uint8_t>{1, 2, 3, 4, 5, 6})),
                make_AudioDevice(make_ADD_BtLeHeadset(),
                                 AudioDeviceAddress::make<AudioDeviceAddress::Tag::mac>(
                                         std::vector<uint8_t>{1, 2, 3, 4, 5, 6})),
                make_AudioDevice(make_ADD_BtLeBroadcast(),
                                 AudioDeviceAddress::make<AudioDeviceAddress::Tag::id>("42")),
                make_AudioDevice(make_ADD_IpV4Device(),
                                 AudioDeviceAddress::make<AudioDeviceAddress::Tag::ipv4>(
                                         std::vector<uint8_t>{192, 168, 0, 1})),
                make_AudioDevice(make_ADD_UsbHeadset(),
                                 AudioDeviceAddress::make<AudioDeviceAddress::Tag::alsa>(
                                         std::vector<int32_t>{1, 2}))));

class AudioFormatDescriptionRoundTripTest : public testing::TestWithParam<AudioFormatDescription> {
};
TEST_P(AudioFormatDescriptionRoundTripTest, Aidl2Legacy2Aidl) {
    const auto initial = GetParam();
    auto conv = aidl2legacy_AudioFormatDescription_audio_format_t(initial);
    ASSERT_TRUE(conv.ok());
    auto convBack = legacy2aidl_audio_format_t_AudioFormatDescription(conv.value());
    ASSERT_TRUE(convBack.ok());
    EXPECT_EQ(initial, convBack.value());
}
INSTANTIATE_TEST_SUITE_P(AudioFormatDescriptionRoundTrip, AudioFormatDescriptionRoundTripTest,
                         testing::Values(make_AFD_Invalid(), AudioFormatDescription{},
                                         make_AFD_Pcm16Bit()));

AudioPortConfigFw createAudioPortConfigFw(const AudioChannelLayout& layout,
                                          const AudioFormatDescription& format,
                                          const AudioDeviceDescription& device) {
    const bool isInput = device.type < AudioDeviceType::OUT_DEFAULT;
    AudioPortConfigFw result;
    result.hal.id = 43;
    result.hal.portId = 42;
    Int sr44100;
    sr44100.value = 44100;
    result.hal.sampleRate = sr44100;
    result.hal.channelMask = layout;
    result.hal.format = format;
    AudioGainConfig gain;
    gain.mode = 1 << static_cast<int>(AudioGainMode::JOINT);
    gain.values = std::vector<int32_t>({100});
    result.hal.gain = gain;
    AudioPortDeviceExt ext;
    AudioDevice audioDevice;
    audioDevice.type = device;
    ext.device = audioDevice;
    result.hal.ext = ext;
    result.sys.role = isInput ? AudioPortRole::SOURCE : AudioPortRole::SINK;
    result.sys.type = AudioPortType::DEVICE;
    AudioPortDeviceExtSys sysDevice;
    sysDevice.hwModule = 1;
    result.sys.ext = sysDevice;
    return result;
}

using AudioPortConfigParam =
        std::tuple<AudioChannelLayout, AudioFormatDescription, AudioDeviceDescription>;
class AudioPortConfigRoundTripTest : public testing::TestWithParam<AudioPortConfigParam> {};
TEST_P(AudioPortConfigRoundTripTest, Aidl2Legacy2Aidl) {
    const AudioChannelLayout layout = std::get<0>(GetParam());
    const AudioFormatDescription format = std::get<1>(GetParam());
    const AudioDeviceDescription device = std::get<2>(GetParam());
    const bool isInput = device.type < AudioDeviceType::OUT_DEFAULT;
    AudioPortConfigFw initial = createAudioPortConfigFw(layout, format, device);
    {
        audio_port_config conv{};
        int32_t portId = -1;
        status_t status =
                aidl2legacy_AudioPortConfig_audio_port_config(initial.hal, isInput, &conv, &portId);
        ASSERT_EQ(OK, status);
        EXPECT_NE(-1, portId);
        auto convBack = legacy2aidl_audio_port_config_AudioPortConfig(conv, isInput, portId);
        ASSERT_TRUE(convBack.ok());
        EXPECT_EQ(initial.hal, convBack.value());
    }
    {
        int32_t portId = -1;
        auto conv = aidl2legacy_AudioPortConfigFw_audio_port_config(initial, &portId);
        ASSERT_TRUE(conv.ok());
        EXPECT_NE(-1, portId);
        auto convBack = legacy2aidl_audio_port_config_AudioPortConfigFw(conv.value(), portId);
        ASSERT_TRUE(convBack.ok());
        EXPECT_EQ(initial, convBack.value());
    }
}
INSTANTIATE_TEST_SUITE_P(
        AudioPortConfig, AudioPortConfigRoundTripTest,
        testing::Combine(testing::Values(make_ACL_Stereo(), make_ACL_ChannelIndex2()),
                         testing::Values(make_AFD_Pcm16Bit()),
                         testing::Values(make_ADD_DefaultIn(), make_ADD_DefaultOut(),
                                         make_ADD_WiredHeadset())));

class AudioPortFwRoundTripTest : public testing::TestWithParam<AudioDeviceDescription> {
  public:
    AudioProfile createProfile(const AudioFormatDescription& format,
                               const std::vector<AudioChannelLayout>& channelMasks,
                               const std::vector<int32_t>& sampleRates) {
        AudioProfile profile;
        profile.format = format;
        profile.channelMasks = channelMasks;
        profile.sampleRates = sampleRates;
        return profile;
    }
};
TEST_P(AudioPortFwRoundTripTest, Aidl2Legacy2Aidl) {
    const AudioDeviceDescription device = GetParam();
    const bool isInput = device.type < AudioDeviceType::OUT_DEFAULT;
    AudioPortFw initial;
    initial.hal.id = 42;
    initial.hal.profiles.push_back(createProfile(
            make_AFD_Pcm16Bit(), {make_ACL_Stereo(), make_ACL_ChannelIndex2()}, {44100, 48000}));
    if (isInput) {
        initial.hal.flags = AudioIoFlags::make<AudioIoFlags::Tag::input>(0);
    } else {
        initial.hal.flags = AudioIoFlags::make<AudioIoFlags::Tag::output>(0);
    }
    AudioGain initialGain;
    initialGain.mode = 1 << static_cast<int>(AudioGainMode::JOINT);
    initialGain.channelMask = make_ACL_Stereo();
    initial.hal.gains.push_back(initialGain);
    AudioPortDeviceExt initialExt;
    AudioDevice initialDevice;
    initialDevice.type = device;
    initialExt.device = initialDevice;
    initial.hal.ext = initialExt;
    {
        auto conv = aidl2legacy_AudioPort_audio_port_v7(initial.hal, isInput);
        ASSERT_TRUE(conv.ok());
        auto convBack = legacy2aidl_audio_port_v7_AudioPort(conv.value(), isInput);
        ASSERT_TRUE(convBack.ok());
        EXPECT_EQ(initial.hal, convBack.value());
    }
    initial.sys.role = isInput ? AudioPortRole::SOURCE : AudioPortRole::SINK;
    initial.sys.type = AudioPortType::DEVICE;
    initial.sys.profiles.resize(initial.hal.profiles.size());
    initial.sys.gains.resize(initial.hal.gains.size());
    initial.sys.activeConfig =
            createAudioPortConfigFw(make_ACL_Stereo(), make_AFD_Pcm16Bit(), device);
    initial.sys.activeConfig.hal.flags = initial.hal.flags;
    AudioPortDeviceExtSys initialSysDevice;
    initialSysDevice.hwModule = 1;
    initial.sys.ext = initialSysDevice;
    {
        auto conv = aidl2legacy_AudioPortFw_audio_port_v7(initial);
        ASSERT_TRUE(conv.ok());
        auto convBack = legacy2aidl_audio_port_v7_AudioPortFw(conv.value());
        ASSERT_TRUE(convBack.ok());
        EXPECT_EQ(initial, convBack.value());
    }
}
INSTANTIATE_TEST_SUITE_P(AudioPortFw, AudioPortFwRoundTripTest,
                         testing::Values(make_ADD_DefaultIn(), make_ADD_DefaultOut(),
                                         make_ADD_WiredHeadset()));

class AudioDirectModeRoundTripTest : public testing::TestWithParam<AudioDirectMode> {};
TEST_P(AudioDirectModeRoundTripTest, Aidl2Legacy2Aidl) {
    const auto initial = GetParam();
    auto conv = aidl2legacy_AudioDirectMode_audio_direct_mode_t(initial);
    ASSERT_TRUE(conv.ok());
    auto convBack = legacy2aidl_audio_direct_mode_t_AudioDirectMode(conv.value());
    ASSERT_TRUE(convBack.ok());
    EXPECT_EQ(initial, convBack.value());
}
INSTANTIATE_TEST_SUITE_P(AudioDirectMode, AudioDirectModeRoundTripTest,
                         testing::Values(AudioDirectMode::NONE, AudioDirectMode::OFFLOAD,
                                         AudioDirectMode::OFFLOAD_GAPLESS,
                                         AudioDirectMode::BITSTREAM));

class AudioStandardRoundTripTest : public testing::TestWithParam<AudioStandard> {};
TEST_P(AudioStandardRoundTripTest, Aidl2Legacy2Aidl) {
    const auto initial = GetParam();
    auto conv = aidl2legacy_AudioStandard_audio_standard_t(initial);
    ASSERT_TRUE(conv.ok());
    auto convBack = legacy2aidl_audio_standard_t_AudioStandard(conv.value());
    ASSERT_TRUE(convBack.ok());
    EXPECT_EQ(initial, convBack.value());
}
INSTANTIATE_TEST_SUITE_P(AudioStandard, AudioStandardRoundTripTest,
                         testing::Values(AudioStandard::NONE, AudioStandard::EDID,
                                         AudioStandard::SADB, AudioStandard::VSADB));

class AudioEncapsulationMetadataTypeRoundTripTest
    : public testing::TestWithParam<AudioEncapsulationMetadataType> {};
TEST_P(AudioEncapsulationMetadataTypeRoundTripTest, Aidl2Legacy2Aidl) {
    const auto initial = GetParam();
    auto conv =
            aidl2legacy_AudioEncapsulationMetadataType_audio_encapsulation_metadata_type_t(initial);
    ASSERT_TRUE(conv.ok());
    auto convBack = legacy2aidl_audio_encapsulation_metadata_type_t_AudioEncapsulationMetadataType(
            conv.value());
    ASSERT_TRUE(convBack.ok());
    EXPECT_EQ(initial, convBack.value());
}
INSTANTIATE_TEST_SUITE_P(AudioEncapsulationMetadataType,
                         AudioEncapsulationMetadataTypeRoundTripTest,
                         testing::Values(AudioEncapsulationMetadataType::NONE,
                                         AudioEncapsulationMetadataType::FRAMEWORK_TUNER,
                                         AudioEncapsulationMetadataType::DVB_AD_DESCRIPTOR));

class AudioGainModeRoundTripTest : public testing::TestWithParam<AudioGainMode> {};
TEST_P(AudioGainModeRoundTripTest, Aidl2Legacy2Aidl) {
    const auto initial = GetParam();
    auto conv = aidl2legacy_AudioGainMode_audio_gain_mode_t(initial);
    ASSERT_TRUE(conv.ok());
    auto convBack = legacy2aidl_audio_gain_mode_t_AudioGainMode(conv.value());
    ASSERT_TRUE(convBack.ok());
    EXPECT_EQ(initial, convBack.value());
}
INSTANTIATE_TEST_SUITE_P(AudioGainMode, AudioGainModeRoundTripTest,
                         testing::Values(AudioGainMode::JOINT, AudioGainMode::CHANNELS,
                                         AudioGainMode::RAMP));

TEST(AudioTrackSecondaryOutputInfoRoundTripTest, Aidl2Legacy2Aidl) {
    const auto initial = make_TrackSecondaryOutputInfo();
    auto conv = aidl2legacy_TrackSecondaryOutputInfo_TrackSecondaryOutputInfoPair(initial);
    ASSERT_TRUE(conv.ok());
    auto convBack = legacy2aidl_TrackSecondaryOutputInfoPair_TrackSecondaryOutputInfo(conv.value());
    ASSERT_TRUE(convBack.ok());
    EXPECT_EQ(initial, convBack.value());
}

using ExtraAudioDescriptorParam = std::tuple<AudioStandard, AudioEncapsulationType>;
class ExtraAudioDescriptorRoundTripTest : public testing::TestWithParam<ExtraAudioDescriptorParam> {
};
TEST_P(ExtraAudioDescriptorRoundTripTest, Aidl2Legacy2Aidl) {
    ExtraAudioDescriptor initial =
            make_ExtraAudioDescriptor(std::get<0>(GetParam()), std::get<1>(GetParam()));
    auto conv = aidl2legacy_ExtraAudioDescriptor_audio_extra_audio_descriptor(initial);
    ASSERT_TRUE(conv.ok());
    auto convBack = legacy2aidl_audio_extra_audio_descriptor_ExtraAudioDescriptor(conv.value());
    ASSERT_TRUE(convBack.ok());
    EXPECT_EQ(initial, convBack.value());
}

INSTANTIATE_TEST_SUITE_P(
        ExtraAudioDescriptor, ExtraAudioDescriptorRoundTripTest,
        testing::Values(std::make_tuple(AudioStandard::NONE, AudioEncapsulationType::NONE),
                        std::make_tuple(AudioStandard::EDID, AudioEncapsulationType::NONE),
                        std::make_tuple(AudioStandard::EDID, AudioEncapsulationType::IEC61937),
                        std::make_tuple(AudioStandard::SADB, AudioEncapsulationType::NONE),
                        std::make_tuple(AudioStandard::SADB, AudioEncapsulationType::IEC61937),
                        std::make_tuple(AudioStandard::VSADB, AudioEncapsulationType::NONE),
                        std::make_tuple(AudioStandard::VSADB, AudioEncapsulationType::IEC61937)));

TEST(AudioPortSessionExtRoundTripTest, Aidl2Legacy2Aidl) {
    const int32_t initial = 7;
    auto conv = aidl2legacy_int32_t_audio_port_session_ext(initial);
    ASSERT_TRUE(conv.ok());
    auto convBack = legacy2aidl_audio_port_session_ext_int32_t(conv.value());
    ASSERT_TRUE(convBack.ok());
    EXPECT_EQ(initial, convBack.value());
}

class AudioGainTest : public testing::TestWithParam<bool> {};
TEST_P(AudioGainTest, Legacy2Aidl2Legacy) {
    audio_port_v7 port;
    port.num_gains = 2;
    port.gains[0] = {.mode = AUDIO_GAIN_MODE_JOINT,
                     .channel_mask = AUDIO_CHANNEL_IN_STEREO,
                     .min_value = -3200,
                     .max_value = 600,
                     .default_value = 0,
                     .step_value = 100,
                     .min_ramp_ms = 10,
                     .max_ramp_ms = 20};
    port.gains[1] = {.mode = AUDIO_GAIN_MODE_JOINT,
                     .channel_mask = AUDIO_CHANNEL_IN_MONO,
                     .min_value = -8800,
                     .max_value = 4000,
                     .default_value = 0,
                     .step_value = 100,
                     .min_ramp_ms = 192,
                     .max_ramp_ms = 224};

    const auto isInput = GetParam();
    for (int i = 0; i < port.num_gains; i++) {
        auto initial = port.gains[i];
        auto conv = legacy2aidl_audio_gain_AudioGain(initial, isInput);
        ASSERT_TRUE(conv.ok());
        auto convBack = aidl2legacy_AudioGain_audio_gain(conv.value(), isInput);
        ASSERT_TRUE(convBack.ok());
        EXPECT_EQ(initial.mode, convBack.value().mode);
        EXPECT_EQ(initial.channel_mask, convBack.value().channel_mask);
        EXPECT_EQ(initial.min_value, convBack.value().min_value);
        EXPECT_EQ(initial.max_value, convBack.value().max_value);
        EXPECT_EQ(initial.default_value, convBack.value().default_value);
        EXPECT_EQ(initial.step_value, convBack.value().step_value);
        EXPECT_EQ(initial.min_ramp_ms, convBack.value().min_ramp_ms);
        EXPECT_EQ(initial.max_ramp_ms, convBack.value().max_ramp_ms);
    }
}
INSTANTIATE_TEST_SUITE_P(AudioGain, AudioGainTest, testing::Values(true, false));

TEST(AudioMicrophoneInfoFw, Aidl2Legacy2Aidl) {
    media::MicrophoneInfoFw initial{};
    // HALs must return at least 1 element in channelMapping. The zero value is 'UNUSED'.
    initial.dynamic.channelMapping.resize(1);
    auto conv = aidl2legacy_MicrophoneInfoFw_audio_microphone_characteristic_t(initial);
    ASSERT_TRUE(conv.ok());
    auto convBack = legacy2aidl_audio_microphone_characteristic_t_MicrophoneInfoFw(conv.value());
    ASSERT_TRUE(convBack.ok());
    EXPECT_EQ(initial, convBack.value());
}

TEST(AudioMicrophoneInfoFw, UnknownValues) {
    {
        media::MicrophoneInfoFw initial;
        initial.dynamic.channelMapping.resize(1);
        initial.info.indexInTheGroup = MicrophoneInfo::INDEX_IN_THE_GROUP_UNKNOWN;
        auto conv = aidl2legacy_MicrophoneInfoFw_audio_microphone_characteristic_t(initial);
        ASSERT_TRUE(conv.ok());
        auto convBack =
                legacy2aidl_audio_microphone_characteristic_t_MicrophoneInfoFw(conv.value());
        ASSERT_TRUE(convBack.ok());
        EXPECT_EQ(initial, convBack.value());
    }
    for (const auto f : {&audio_microphone_characteristic_t::sensitivity,
                         &audio_microphone_characteristic_t::max_spl,
                         &audio_microphone_characteristic_t::min_spl}) {
        audio_microphone_characteristic_t mic{};
        if (f == &audio_microphone_characteristic_t::sensitivity) {
            mic.*f = AUDIO_MICROPHONE_SENSITIVITY_UNKNOWN;
        } else {
            mic.*f = AUDIO_MICROPHONE_SPL_UNKNOWN;
        }
        auto aidl = legacy2aidl_audio_microphone_characteristic_t_MicrophoneInfoFw(mic);
        ASSERT_TRUE(aidl.ok());
        EXPECT_FALSE(aidl.value().info.sensitivity.has_value());
    }
    for (const auto f : {&audio_microphone_characteristic_t::geometric_location,
                         &audio_microphone_characteristic_t::orientation}) {
        for (const auto c : {&audio_microphone_coordinate::x, &audio_microphone_coordinate::y,
                             &audio_microphone_coordinate::z}) {
            audio_microphone_characteristic_t mic{};
            mic.*f.*c = AUDIO_MICROPHONE_COORDINATE_UNKNOWN;
            auto conv = legacy2aidl_audio_microphone_characteristic_t_MicrophoneInfoFw(mic);
            ASSERT_TRUE(conv.ok());
            const auto& aidl = conv.value();
            if (f == &audio_microphone_characteristic_t::geometric_location) {
                EXPECT_FALSE(aidl.info.position.has_value());
                EXPECT_TRUE(aidl.info.orientation.has_value());
            } else {
                EXPECT_TRUE(aidl.info.position.has_value());
                EXPECT_FALSE(aidl.info.orientation.has_value());
            }
        }
    }
}

TEST(AudioMicrophoneInfoFw, ChannelMapping) {
    audio_microphone_characteristic_t mic{};
    mic.channel_mapping[1] = AUDIO_MICROPHONE_CHANNEL_MAPPING_DIRECT;
    mic.channel_mapping[3] = AUDIO_MICROPHONE_CHANNEL_MAPPING_PROCESSED;
    auto conv = legacy2aidl_audio_microphone_characteristic_t_MicrophoneInfoFw(mic);
    ASSERT_TRUE(conv.ok());
    const auto& aidl = conv.value();
    EXPECT_EQ(4, aidl.dynamic.channelMapping.size());
    EXPECT_EQ(MicrophoneDynamicInfo::ChannelMapping::UNUSED, aidl.dynamic.channelMapping[0]);
    EXPECT_EQ(MicrophoneDynamicInfo::ChannelMapping::DIRECT, aidl.dynamic.channelMapping[1]);
    EXPECT_EQ(MicrophoneDynamicInfo::ChannelMapping::UNUSED, aidl.dynamic.channelMapping[2]);
    EXPECT_EQ(MicrophoneDynamicInfo::ChannelMapping::PROCESSED, aidl.dynamic.channelMapping[3]);
}

TEST(AudioInputFlags, Aidl2Legacy2Aidl) {
    for (auto flag : enum_range<AudioInputFlags>()) {
        int32_t aidlMask = 1 << static_cast<int32_t>(flag);
        auto convMask = aidl2legacy_int32_t_audio_input_flags_t_mask(aidlMask);
        ASSERT_TRUE(convMask.ok());
        ASSERT_EQ(1, __builtin_popcount(convMask.value()));
        auto convFlag = legacy2aidl_audio_input_flags_t_AudioInputFlags(convMask.value());
        ASSERT_TRUE(convFlag.ok());
        EXPECT_EQ(flag, convFlag.value());
    }
}

TEST(AudioOutputFlags, Aidl2Legacy2Aidl) {
    for (auto flag : enum_range<AudioOutputFlags>()) {
        int32_t aidlMask = 1 << static_cast<int32_t>(flag);
        auto convMask = aidl2legacy_int32_t_audio_output_flags_t_mask(aidlMask);
        ASSERT_TRUE(convMask.ok());
        ASSERT_EQ(1, __builtin_popcount(convMask.value()));
        auto convFlag = legacy2aidl_audio_output_flags_t_AudioOutputFlags(convMask.value());
        ASSERT_TRUE(convFlag.ok());
        EXPECT_EQ(flag, convFlag.value());
    }
}
