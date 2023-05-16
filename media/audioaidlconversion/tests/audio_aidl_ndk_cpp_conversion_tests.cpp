/*
 * Copyright (C) 2023 The Android Open Source Project
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
#include <type_traits>

#include <gtest/gtest.h>

#include <media/AidlConversionNdkCpp.h>

namespace {
template<typename> struct mf_traits {};
template<class T, class U> struct mf_traits<U T::*> {
    using member_type = U;
};
}  // namespace

// Provide value printers for types generated from AIDL
// They need to be in the same namespace as the types we intend to print
#define DEFINE_PRINTING_TEMPLATES()
    template <typename P>                                                                         \
    std::enable_if_t<std::is_function_v<typename mf_traits<decltype(&P::toString)>::member_type>, \
            std::ostream&> operator<<(std::ostream& os, const P& p) {                             \
        return os << p.toString();                                                                \
    }                                                                                             \
    template <typename E>                                                                         \
    std::enable_if_t<std::is_enum_v<E>, std::ostream&> operator<<(std::ostream& os, const E& e) { \
        return os << toString(e);                                                                 \
    }

namespace aidl::android::media::audio::common {
DEFINE_PRINTING_TEMPLATES();
}  // namespace aidl::android::media::audio::common
namespace android::hardware::audio::common {
DEFINE_PRINTING_TEMPLATES();
}  // namespace android::hardware::audio::common
#undef DEFINE_PRINTING_TEMPLATES

using namespace android;

namespace {

using namespace ::aidl::android::media::audio::common;

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

}  // namespace

// There is no reason to write test for every type which gets converted via parcelable
// since the conversion code is all the same.

class AudioFormatDescriptionRoundTripTest :
        public testing::TestWithParam<::aidl::android::media::audio::common::AudioFormatDescription>
{
};
TEST_P(AudioFormatDescriptionRoundTripTest, Ndk2Cpp2Ndk) {
    const auto& initial = GetParam();
    auto conv = ndk2cpp_AudioFormatDescription(initial);
    ASSERT_TRUE(conv.ok());
    auto convBack = cpp2ndk_AudioFormatDescription(conv.value());
    ASSERT_TRUE(convBack.ok());
    EXPECT_EQ(initial, convBack.value());
}
INSTANTIATE_TEST_SUITE_P(AudioFormatDescriptionRoundTrip, AudioFormatDescriptionRoundTripTest,
        testing::Values(make_AFD_Invalid(), make_AFD_Default(), make_AFD_Pcm16Bit(),
                make_AFD_Bitstream(), make_AFD_Encap(), make_AFD_Encap_with_Enc()));

TEST(AudioPortRoundTripTest, Ndk2Cpp2Ndk) {
    const AudioPort initial;
    auto conv = ndk2cpp_AudioPort(initial);
    ASSERT_TRUE(conv.ok());
    auto convBack = cpp2ndk_AudioPort(conv.value());
    ASSERT_TRUE(convBack.ok());
    EXPECT_EQ(initial, convBack.value());
}
