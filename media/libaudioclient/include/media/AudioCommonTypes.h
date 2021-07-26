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

#include <system/audio.h>
#include <system/audio_policy.h>
#include <binder/Parcelable.h>

namespace android {

enum product_strategy_t : uint32_t;
const product_strategy_t PRODUCT_STRATEGY_NONE = static_cast<product_strategy_t>(-1);

using AttributesVector = std::vector<audio_attributes_t>;
using StreamTypeVector = std::vector<audio_stream_type_t>;

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

