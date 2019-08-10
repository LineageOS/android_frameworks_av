/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include <set>
#include <vector>

#include <system/audio.h>

namespace android {

using ChannelMaskSet = std::set<audio_channel_mask_t>;
using FormatSet = std::set<audio_format_t>;
using SampleRateSet = std::set<uint32_t>;

using FormatVector = std::vector<audio_format_t>;

static inline ChannelMaskSet asInMask(const ChannelMaskSet& channelMasks) {
    ChannelMaskSet inMaskSet;
    for (const auto &channel : channelMasks) {
        if (audio_channel_mask_out_to_in(channel) != AUDIO_CHANNEL_INVALID) {
            inMaskSet.insert(audio_channel_mask_out_to_in(channel));
        }
    }
    return inMaskSet;
}

static inline ChannelMaskSet asOutMask(const ChannelMaskSet& channelMasks) {
    ChannelMaskSet outMaskSet;
    for (const auto &channel : channelMasks) {
        if (audio_channel_mask_in_to_out(channel) != AUDIO_CHANNEL_INVALID) {
            outMaskSet.insert(audio_channel_mask_in_to_out(channel));
        }
    }
    return outMaskSet;
}

} // namespace android