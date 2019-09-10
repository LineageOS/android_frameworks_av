/*
 * Copyright (C) 2015 The Android Open Source Project
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

#include <media/AudioProfile.h>
#include <system/audio.h>

namespace android {

void sortAudioProfiles(AudioProfileVector &audioProfileVector);

ssize_t addAudioProfileAndSort(AudioProfileVector &audioProfileVector,
                               const sp<AudioProfile> &profile);

// One audio profile will be added for each format supported by Audio HAL
void addProfilesForFormats(AudioProfileVector &audioProfileVector,
                           const FormatVector &formatVector);

// This API is intended to be used by the policy manager once retrieving capabilities
// for a profile with dynamic format, rate and channels attributes
void addDynamicAudioProfileAndSort(AudioProfileVector &audioProfileVector,
                                   const sp<AudioProfile> &profileToAdd);

void appendAudioProfiles(AudioProfileVector &audioProfileVector,
                         const AudioProfileVector &audioProfileVectorToAppend);

status_t checkExactProfile(const AudioProfileVector &audioProfileVector,
                           const uint32_t samplingRate,
                           audio_channel_mask_t channelMask,
                           audio_format_t format);

status_t checkCompatibleProfile(const AudioProfileVector &audioProfileVector,
                                uint32_t &samplingRate,
                                audio_channel_mask_t &channelMask,
                                audio_format_t &format,
                                audio_port_type_t portType,
                                audio_port_role_t portRole);

// Assuming that this profile vector contains input profiles,
// find the best matching config from 'outputProfiles', according to
// the given preferences for audio formats and channel masks.
// Note: std::vectors are used because specialized containers for formats
//       and channels can be sorted and use their own ordering.
status_t findBestMatchingOutputConfig(
        const AudioProfileVector &audioProfileVector,
        const AudioProfileVector &outputProfileVector,
        const std::vector<audio_format_t> &preferredFormatVector, // order: most pref -> least pref
        const std::vector<audio_channel_mask_t> &preferredOutputChannelVector,
        bool preferHigherSamplingRates,
        audio_config_base &bestOutputConfig);


} // namespace android