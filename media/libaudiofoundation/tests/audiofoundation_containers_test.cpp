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

#include <gtest/gtest.h>

#include <media/AudioContainers.h>

namespace android {

const static AudioProfileAttributesMultimap AUDIO_PROFILE_ATTRIBUTES = {
        {AUDIO_FORMAT_PCM_16_BIT, {{44100, 48000},
                                   {AUDIO_CHANNEL_OUT_STEREO, AUDIO_CHANNEL_OUT_7POINT1}}},
        {AUDIO_FORMAT_PCM_16_BIT, {{96000},
                                   {AUDIO_CHANNEL_OUT_STEREO}}},
        {AUDIO_FORMAT_PCM_8_24_BIT, {{48000},
                                     {AUDIO_CHANNEL_OUT_STEREO}}}
};

TEST(PopulateAudioProfilesTest, AllAttributesMatches) {
    const AudioProfileAttributesMultimap expected = {
            {AUDIO_FORMAT_PCM_16_BIT, {{44100, 48000},
                                       {AUDIO_CHANNEL_OUT_STEREO, AUDIO_CHANNEL_OUT_7POINT1}}},
            {AUDIO_FORMAT_PCM_16_BIT, {{96000},
                                       {AUDIO_CHANNEL_OUT_STEREO}}}
    };
    const audio_format_t format = AUDIO_FORMAT_PCM_16_BIT;
    const SampleRateSet allSampleRates = {44100, 48000, 96000};
    const ChannelMaskSet allChannelMasks = {AUDIO_CHANNEL_OUT_STEREO, AUDIO_CHANNEL_OUT_7POINT1};

    audio_profile profiles[AUDIO_PORT_MAX_AUDIO_PROFILES];
    uint32_t numProfiles = 0;
    populateAudioProfiles(AUDIO_PROFILE_ATTRIBUTES, format, allChannelMasks, allSampleRates,
                          profiles, &numProfiles);
    ASSERT_EQ(expected, createAudioProfilesAttrMap(profiles, 0, numProfiles));
}

TEST(PopulateAudioProfilesTest, AttributesNotInAllValues) {
    const AudioProfileAttributesMultimap expected = {
            {AUDIO_FORMAT_PCM_16_BIT, {{48000},
                                       {AUDIO_CHANNEL_OUT_STEREO, AUDIO_CHANNEL_OUT_7POINT1}}},
            {AUDIO_FORMAT_PCM_16_BIT, {{96000},
                                       {AUDIO_CHANNEL_OUT_STEREO}}}
    };
    const audio_format_t format = AUDIO_FORMAT_PCM_16_BIT;
    const SampleRateSet allSampleRates = {48000, 96000};
    const ChannelMaskSet allChannelMasks = {AUDIO_CHANNEL_OUT_STEREO, AUDIO_CHANNEL_OUT_7POINT1};

    audio_profile profiles[AUDIO_PORT_MAX_AUDIO_PROFILES];
    uint32_t numProfiles = 0;
    populateAudioProfiles(AUDIO_PROFILE_ATTRIBUTES, format, allChannelMasks, allSampleRates,
            profiles, &numProfiles);
    ASSERT_EQ(expected, createAudioProfilesAttrMap(profiles, 0, numProfiles));
}

TEST(PopulateAudioProfilesTest, AllValuesNotInAttributes) {
    const AudioProfileAttributesMultimap expected = {
            {AUDIO_FORMAT_PCM_16_BIT, {{48000},
                                       {AUDIO_CHANNEL_OUT_STEREO, AUDIO_CHANNEL_OUT_7POINT1}}},
            {AUDIO_FORMAT_PCM_16_BIT, {{96000},
                                       {AUDIO_CHANNEL_OUT_STEREO}}},
            {AUDIO_FORMAT_PCM_16_BIT, {{88200},
                                       {AUDIO_CHANNEL_OUT_MONO, AUDIO_CHANNEL_OUT_STEREO,
                                        AUDIO_CHANNEL_OUT_7POINT1}}},
            {AUDIO_FORMAT_PCM_16_BIT, {{48000, 88200, 96000},
                                       {AUDIO_CHANNEL_OUT_MONO}}}
    };
    const audio_format_t format = AUDIO_FORMAT_PCM_16_BIT;
    const SampleRateSet allSampleRates = {48000, 88200, 96000};
    const ChannelMaskSet allChannelMasks =
            {AUDIO_CHANNEL_OUT_MONO, AUDIO_CHANNEL_OUT_STEREO, AUDIO_CHANNEL_OUT_7POINT1};

    audio_profile profiles[AUDIO_PORT_MAX_AUDIO_PROFILES];
    uint32_t numProfiles = 0;
    populateAudioProfiles(AUDIO_PROFILE_ATTRIBUTES, format, allChannelMasks, allSampleRates,
            profiles, &numProfiles);
    ASSERT_EQ(expected, createAudioProfilesAttrMap(profiles, 0, numProfiles));
}

TEST(PopulateAudioProfilesTest, NoOverflow) {
    const audio_format_t format = AUDIO_FORMAT_PCM_16_BIT;
    const SampleRateSet allSampleRates = {48000, 88200, 96000};
    const ChannelMaskSet allChannelMasks =
            {AUDIO_CHANNEL_OUT_MONO, AUDIO_CHANNEL_OUT_STEREO, AUDIO_CHANNEL_OUT_7POINT1};

    audio_profile profiles[AUDIO_PORT_MAX_AUDIO_PROFILES];
    const uint32_t expectedNumProfiles = 4;
    for (uint32_t i = 0; i <= AUDIO_PORT_MAX_AUDIO_PROFILES; ++i) {
        uint32_t numProfiles = 0;
        populateAudioProfiles(AUDIO_PROFILE_ATTRIBUTES, format, allChannelMasks, allSampleRates,
                              profiles, &numProfiles, i);
        ASSERT_EQ(std::min(i, expectedNumProfiles), numProfiles);
    }
}

} // namespace android
