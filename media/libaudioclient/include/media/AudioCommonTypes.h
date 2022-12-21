/*
 * Copyright (C) 2018 The Android Open Source Project
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


#pragma once

#include <functional>

#include <android/media/audio/common/AudioChannelLayout.h>
#include <android/media/audio/common/AudioDeviceDescription.h>
#include <android/media/audio/common/AudioFormatDescription.h>
#include <binder/Parcelable.h>
#include <system/audio.h>
#include <system/audio_policy.h>

namespace {
// see boost::hash_combine
#if defined(__clang__)
__attribute__((no_sanitize("unsigned-integer-overflow")))
#endif
static size_t hash_combine(size_t seed, size_t v) {
    return std::hash<size_t>{}(v) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
}
}

namespace std {

// Note: when extending the types hashed below we need to account for the
// possibility of processing types belonging to different versions of the type,
// e.g. a HAL may be using a previous version of the AIDL interface.

template<> struct hash<android::media::audio::common::AudioChannelLayout>
{
    std::size_t operator()(
            const android::media::audio::common::AudioChannelLayout& acl) const noexcept {
        using Tag = android::media::audio::common::AudioChannelLayout::Tag;
        const size_t seed = std::hash<Tag>{}(acl.getTag());
        switch (acl.getTag()) {
            case Tag::none:
                return hash_combine(seed, std::hash<int32_t>{}(acl.get<Tag::none>()));
            case Tag::invalid:
                return hash_combine(seed, std::hash<int32_t>{}(acl.get<Tag::invalid>()));
            case Tag::indexMask:
                return hash_combine(seed, std::hash<int32_t>{}(acl.get<Tag::indexMask>()));
            case Tag::layoutMask:
                return hash_combine(seed, std::hash<int32_t>{}(acl.get<Tag::layoutMask>()));
            case Tag::voiceMask:
                return hash_combine(seed, std::hash<int32_t>{}(acl.get<Tag::voiceMask>()));
        }
        return seed;
    }
};

template<> struct hash<android::media::audio::common::AudioDeviceDescription>
{
    std::size_t operator()(
            const android::media::audio::common::AudioDeviceDescription& add) const noexcept {
        return hash_combine(
                std::hash<android::media::audio::common::AudioDeviceType>{}(add.type),
                std::hash<std::string>{}(add.connection));
    }
};

template<> struct hash<android::media::audio::common::AudioFormatDescription>
{
    std::size_t operator()(
            const android::media::audio::common::AudioFormatDescription& afd) const noexcept {
        return hash_combine(
                std::hash<android::media::audio::common::AudioFormatType>{}(afd.type),
                hash_combine(
                        std::hash<android::media::audio::common::PcmType>{}(afd.pcm),
                        std::hash<std::string>{}(afd.encoding)));
    }
};
}  // namespace std

namespace android {

enum product_strategy_t : uint32_t;
const product_strategy_t PRODUCT_STRATEGY_NONE = static_cast<product_strategy_t>(-1);

using AttributesVector = std::vector<audio_attributes_t>;
using StreamTypeVector = std::vector<audio_stream_type_t>;
using PortHandleVector = std::vector<audio_port_handle_t>;

using TrackSecondaryOutputsMap = std::map<audio_port_handle_t, std::vector<audio_io_handle_t>>;

constexpr bool operator==(const audio_attributes_t &lhs, const audio_attributes_t &rhs)
{
    return lhs.usage == rhs.usage && lhs.content_type == rhs.content_type &&
            lhs.flags == rhs.flags && (std::strcmp(lhs.tags, rhs.tags) == 0);
}
constexpr bool operator!=(const audio_attributes_t &lhs, const audio_attributes_t &rhs)
{
    return !(lhs==rhs);
}

constexpr bool operator==(const audio_offload_info_t &lhs, const audio_offload_info_t &rhs)
{
    return lhs.version == rhs.version && lhs.size == rhs.size &&
           lhs.sample_rate == rhs.sample_rate && lhs.channel_mask == rhs.channel_mask &&
           lhs.format == rhs.format && lhs.stream_type == rhs.stream_type &&
           lhs.bit_rate == rhs.bit_rate && lhs.duration_us == rhs.duration_us &&
           lhs.has_video == rhs.has_video && lhs.is_streaming == rhs.is_streaming &&
           lhs.bit_width == rhs.bit_width && lhs.offload_buffer_size == rhs.offload_buffer_size &&
           lhs.usage == rhs.usage && lhs.encapsulation_mode == rhs.encapsulation_mode &&
           lhs.content_id == rhs.content_id && lhs.sync_id == rhs.sync_id;
}
constexpr bool operator!=(const audio_offload_info_t &lhs, const audio_offload_info_t &rhs)
{
    return !(lhs==rhs);
}

constexpr bool operator==(const audio_config_t &lhs, const audio_config_t &rhs)
{
    return lhs.sample_rate == rhs.sample_rate && lhs.channel_mask == rhs.channel_mask &&
           lhs.format == rhs.format && lhs.offload_info == rhs.offload_info;
}
constexpr bool operator!=(const audio_config_t &lhs, const audio_config_t &rhs)
{
    return !(lhs==rhs);
}

constexpr bool operator==(const audio_config_base_t &lhs, const audio_config_base_t &rhs)
{
    return lhs.sample_rate == rhs.sample_rate && lhs.channel_mask == rhs.channel_mask &&
           lhs.format == rhs.format;
}
constexpr bool operator!=(const audio_config_base_t &lhs, const audio_config_base_t &rhs)
{
    return !(lhs==rhs);
}

enum volume_group_t : uint32_t;
static const volume_group_t VOLUME_GROUP_NONE = static_cast<volume_group_t>(-1);

} // namespace android
