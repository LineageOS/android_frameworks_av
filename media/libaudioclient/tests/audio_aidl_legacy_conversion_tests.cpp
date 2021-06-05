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

namespace {

size_t afdHash(const media::AudioFormatDescription& afd) {
    return std::hash<media::AudioFormatDescription>{}(afd);
}

media::AudioFormatDescription make_AudioFormatDescription(media::AudioFormatType type) {
    media::AudioFormatDescription result;
    result.type = type;
    return result;
}

media::AudioFormatDescription make_AudioFormatDescription(media::PcmType pcm) {
    auto result = make_AudioFormatDescription(media::AudioFormatType::PCM);
    result.pcm = pcm;
    return result;
}

media::AudioFormatDescription make_AudioFormatDescription(const std::string& encoding) {
    media::AudioFormatDescription result;
    result.encoding = encoding;
    return result;
}

media::AudioFormatDescription make_AudioFormatDescription(media::PcmType transport,
        const std::string& encoding) {
    auto result = make_AudioFormatDescription(encoding);
    result.pcm = transport;
    return result;
}

media::AudioFormatDescription make_AFD_Invalid() {
    return make_AudioFormatDescription(media::AudioFormatType::SYS_RESERVED_INVALID);
}

media::AudioFormatDescription make_AFD_Pcm16Bit() {
    return make_AudioFormatDescription(media::PcmType::INT_16_BIT);
}

media::AudioFormatDescription make_AFD_Bitstream() {
    return make_AudioFormatDescription("example");
}

media::AudioFormatDescription make_AFD_Encap() {
    return make_AudioFormatDescription(media::PcmType::INT_16_BIT, "example.encap");
}

media::AudioFormatDescription make_AFD_Encap_with_Enc() {
    auto afd = make_AFD_Encap();
    afd.encoding += "+example";
    return afd;
}

}  // namespace

// Verify that two independently constructed AFDs have the same hash.
// This ensures that regardless of whether the AFD instance originates
// from, it can be correctly compared to other AFD instance. Thus,
// for example, a 16-bit integer format description provided by HAL
// is identical to the same format description constructed by the framework.
TEST(audio_aidl_legacy_conversion_tests, AudioFormatDescriptionHashIdentity) {
    EXPECT_EQ(afdHash(make_AFD_Invalid()), afdHash(make_AFD_Invalid()));
    EXPECT_EQ(afdHash(media::AudioFormatDescription{}), afdHash(media::AudioFormatDescription{}));
    EXPECT_EQ(afdHash(make_AFD_Pcm16Bit()), afdHash(make_AFD_Pcm16Bit()));
    EXPECT_NE(afdHash(media::AudioFormatDescription{}), afdHash(make_AFD_Invalid()));
    EXPECT_NE(afdHash(media::AudioFormatDescription{}), afdHash(make_AFD_Pcm16Bit()));
    EXPECT_EQ(afdHash(make_AFD_Bitstream()), afdHash(make_AFD_Bitstream()));
    EXPECT_NE(afdHash(make_AFD_Pcm16Bit()), afdHash(make_AFD_Bitstream()));
    EXPECT_EQ(afdHash(make_AFD_Encap()), afdHash(make_AFD_Encap()));
    EXPECT_NE(afdHash(make_AFD_Pcm16Bit()), afdHash(make_AFD_Encap()));
    EXPECT_EQ(afdHash(make_AFD_Encap_with_Enc()), afdHash(make_AFD_Encap_with_Enc()));
    EXPECT_NE(afdHash(make_AFD_Encap()), afdHash(make_AFD_Encap_with_Enc()));
}

class AudioFormatDescriptionRoundTripTest :
        public testing::TestWithParam<media::AudioFormatDescription> {};
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
        testing::Values(make_AFD_Invalid(), media::AudioFormatDescription{}, make_AFD_Pcm16Bit()));
