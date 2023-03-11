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

#include <media/AidlConversionNdk.h>

namespace {
template<typename> struct mf_traits {};
template<class T, class U> struct mf_traits<U T::*> {
    using member_type = U;
};
}  // namespace

// Provide value printers for types generated from AIDL
// They need to be in the same namespace as the types we intend to print
namespace aidl::android::hardware::audio::common {
    template <typename P>
    std::enable_if_t<std::is_function_v<typename mf_traits<decltype(&P::toString)>::member_type>,
            std::ostream&> operator<<(std::ostream& os, const P& p) {
        return os << p.toString();
    }
    template <typename E>
    std::enable_if_t<std::is_enum_v<E>, std::ostream&> operator<<(std::ostream& os, const E& e) {
        return os << toString(e);
    }
}  // namespace aidl::android::hardware::audio::common

using aidl::android::hardware::audio::common::PlaybackTrackMetadata;
using aidl::android::hardware::audio::common::RecordTrackMetadata;
using aidl::android::media::audio::common::AudioSource;
using aidl::android::media::audio::common::AudioUsage;
using namespace aidl::android;   // for conversion functions

TEST(AudioPlaybackTrackMetadata, Aidl2Legacy2Aidl) {
    const PlaybackTrackMetadata initial{ .usage = AudioUsage::UNKNOWN };
    auto conv = aidl2legacy_PlaybackTrackMetadata_playback_track_metadata_v7(initial);
    ASSERT_TRUE(conv.ok());
    auto convBack = legacy2aidl_playback_track_metadata_v7_PlaybackTrackMetadata(conv.value());
    ASSERT_TRUE(convBack.ok());
    EXPECT_EQ(initial, convBack.value());
}

TEST(AudioPlaybackTrackMetadata, NonVendorTags) {
    PlaybackTrackMetadata initial{ .usage = AudioUsage::UNKNOWN };
    initial.tags.emplace_back("random string");  // Must be filtered out.
    initial.tags.emplace_back("VX_GOOGLE_42");
    auto conv = aidl2legacy_PlaybackTrackMetadata_playback_track_metadata_v7(initial);
    ASSERT_TRUE(conv.ok());
    auto convBack = legacy2aidl_playback_track_metadata_v7_PlaybackTrackMetadata(conv.value());
    ASSERT_TRUE(convBack.ok());
    ASSERT_EQ(1, convBack.value().tags.size());
    EXPECT_EQ(initial.tags[1], convBack.value().tags[0]);
}

TEST(AudioRecordTrackMetadata, Aidl2Legacy2Aidl) {
    const RecordTrackMetadata initial{ .source = AudioSource::DEFAULT };
    auto conv = aidl2legacy_RecordTrackMetadata_record_track_metadata_v7(initial);
    ASSERT_TRUE(conv.ok());
    auto convBack = legacy2aidl_record_track_metadata_v7_RecordTrackMetadata(conv.value());
    ASSERT_TRUE(convBack.ok());
    EXPECT_EQ(initial, convBack.value());
}

TEST(AudioRecordTrackMetadata, NonVendorTags) {
    RecordTrackMetadata initial{ .source = AudioSource::DEFAULT };
    initial.tags.emplace_back("random string");  // Must be filtered out.
    initial.tags.emplace_back("VX_GOOGLE_42");
    auto conv = aidl2legacy_RecordTrackMetadata_record_track_metadata_v7(initial);
    ASSERT_TRUE(conv.ok());
    auto convBack = legacy2aidl_record_track_metadata_v7_RecordTrackMetadata(conv.value());
    ASSERT_TRUE(convBack.ok());
    ASSERT_EQ(1, convBack.value().tags.size());
    EXPECT_EQ(initial.tags[1], convBack.value().tags[0]);
}
