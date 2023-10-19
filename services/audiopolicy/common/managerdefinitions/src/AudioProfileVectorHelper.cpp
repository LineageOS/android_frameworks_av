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

#include <algorithm>
#include <set>
#include <string>

#define LOG_TAG "APM::AudioProfileVectorHelper"
//#define LOG_NDEBUG 0

#include <media/AudioContainers.h>
#include <media/AudioResamplerPublic.h>
#include <utils/Errors.h>

#include "AudioProfileVectorHelper.h"
#include "HwModule.h"
#include "PolicyAudioPort.h"
#include "policy.h"

namespace android {

void sortAudioProfiles(AudioProfileVector &audioProfileVector) {
    std::sort(audioProfileVector.begin(), audioProfileVector.end(),
            [](const sp<AudioProfile> & a, const sp<AudioProfile> & b)
            {
                return PolicyAudioPort::compareFormats(a->getFormat(), b->getFormat()) < 0;
            });
}

ssize_t addAudioProfileAndSort(AudioProfileVector &audioProfileVector,
                               const sp<AudioProfile> &profile)
{
    ssize_t ret = audioProfileVector.add(profile);
    // we sort from worst to best, so that AUDIO_FORMAT_DEFAULT is always the first entry.
    sortAudioProfiles(audioProfileVector);
    return ret;
}

sp<AudioProfile> getAudioProfileForFormat(const AudioProfileVector &audioProfileVector,
                                          audio_format_t format)
{
    for (const auto &profile : audioProfileVector) {
        if (profile->getFormat() == format) {
            return profile;
        }
    }
    return nullptr;
}

void setSampleRatesForAudioProfiles(AudioProfileVector &audioProfileVector,
                                    const SampleRateSet &sampleRateSet,
                                    audio_format_t format)
{
    for (const auto &profile : audioProfileVector) {
        if (profile->getFormat() == format && profile->isDynamicRate()) {
            if (profile->hasValidRates()) {
                // Need to create a new profile with same format
                sp<AudioProfile> profileToAdd = new AudioProfile(
                        format, profile->getChannels(), sampleRateSet);
                profileToAdd->setDynamicFormat(true); // need to set to allow cleaning
                addAudioProfileAndSort(audioProfileVector, profileToAdd);
            } else {
                profile->setSampleRates(sampleRateSet);
            }
            return;
        }
    }
}

void setChannelsForAudioProfiles(AudioProfileVector &audioProfileVector,
                                 const ChannelMaskSet &channelMaskSet,
                                 audio_format_t format)
{
    for (const auto &profile : audioProfileVector) {
        if (profile->getFormat() == format && profile->isDynamicChannels()) {
            if (profile->hasValidChannels()) {
                // Need to create a new profile with same format
                sp<AudioProfile> profileToAdd = new AudioProfile(format, channelMaskSet,
                        profile->getSampleRates());
                profileToAdd->setDynamicFormat(true); // need to set to allow cleaning
                addAudioProfileAndSort(audioProfileVector, profileToAdd);
            } else {
                profile->setChannels(channelMaskSet);
            }
            return;
        }
    }
}

void addProfilesForFormats(AudioProfileVector &audioProfileVector, const FormatVector &formatVector)
{
    // Only allow to change the format of dynamic profile
    sp<AudioProfile> dynamicFormatProfile = getAudioProfileForFormat(
            audioProfileVector, gDynamicFormat);
    if (!dynamicFormatProfile) {
        return;
    }
    for (const auto &format : formatVector) {
        sp<AudioProfile> profile = new AudioProfile(format,
                dynamicFormatProfile->getChannels(),
                dynamicFormatProfile->getSampleRates());
        profile->setDynamicFormat(true);
        profile->setDynamicChannels(dynamicFormatProfile->isDynamicChannels());
        profile->setDynamicRate(dynamicFormatProfile->isDynamicRate());
        size_t profileIndex = 0;
        for (; profileIndex < audioProfileVector.size(); profileIndex++) {
            if (profile->equals(audioProfileVector.at(profileIndex))) {
                // The dynamic profile is already there
                break;
            }
        }
        if (profileIndex >= audioProfileVector.size()) {
            // Only add when the dynamic profile is not there
            addAudioProfileAndSort(audioProfileVector, profile);
        }
    }
}

void addDynamicAudioProfileAndSort(AudioProfileVector &audioProfileVector,
                                   const sp<AudioProfile> &profileToAdd)
{
    // Check valid profile to add:
    if (!profileToAdd->hasValidFormat()) {
        ALOGW("Adding dynamic audio profile without valid format");
        return;
    }
    if (!profileToAdd->hasValidChannels() && !profileToAdd->hasValidRates()) {
        FormatVector formats;
        formats.push_back(profileToAdd->getFormat());
        addProfilesForFormats(audioProfileVector, FormatVector(formats));
        return;
    }
    if (!profileToAdd->hasValidChannels() && profileToAdd->hasValidRates()) {
        setSampleRatesForAudioProfiles(
                audioProfileVector, profileToAdd->getSampleRates(), profileToAdd->getFormat());
        return;
    }
    if (profileToAdd->hasValidChannels() && !profileToAdd->hasValidRates()) {
        setChannelsForAudioProfiles(
                audioProfileVector, profileToAdd->getChannels(), profileToAdd->getFormat());
        return;
    }
    const bool originalIsDynamicFormat = profileToAdd->isDynamicFormat();
    profileToAdd->setDynamicFormat(true); // set the format as dynamic to allow removal
    // Go through the list of profile to avoid duplicates
    for (size_t profileIndex = 0; profileIndex < audioProfileVector.size(); profileIndex++) {
        const sp<AudioProfile> &profile = audioProfileVector.at(profileIndex);
        if (profile->isValid() && profile->equals(profileToAdd)) {
            // The same profile is already there, no need to add.
            // Reset `isDynamicProfile` as original value.
            profileToAdd->setDynamicFormat(originalIsDynamicFormat);
            return;
        }
    }
    profileToAdd->setDynamicFormat(true); // set the format as dynamic to allow removal
    addAudioProfileAndSort(audioProfileVector, profileToAdd);
}

void appendAudioProfiles(AudioProfileVector &audioProfileVector,
                         const AudioProfileVector &audioProfileVectorToAppend)
{
    audioProfileVector.insert(audioProfileVector.end(),
                              audioProfileVectorToAppend.begin(),
                              audioProfileVectorToAppend.end());
}

status_t checkExact(const sp<AudioProfile> &audioProfile,
                    uint32_t samplingRate,
                    audio_channel_mask_t channelMask,
                    audio_format_t format)
{
    if (audio_formats_match(format, audioProfile->getFormat()) &&
            audioProfile->supportsChannels(channelMask) &&
            audioProfile->supportsRate(samplingRate)) {
        return NO_ERROR;
    }
    return BAD_VALUE;
}

status_t checkCompatibleSamplingRate(const sp<AudioProfile> &audioProfile,
                                     uint32_t samplingRate,
                                     uint32_t &updatedSamplingRate)
{
    ALOG_ASSERT(samplingRate > 0);

    const SampleRateSet sampleRates = audioProfile->getSampleRates();
    if (sampleRates.empty()) {
        updatedSamplingRate = samplingRate;
        return NO_ERROR;
    }

    // Search for the closest supported sampling rate that is above (preferred)
    // or below (acceptable) the desired sampling rate, within a permitted ratio.
    // The sampling rates are sorted in ascending order.
    auto desiredRate = sampleRates.lower_bound(samplingRate);

    // Prefer to down-sample from a higher sampling rate, as we get the desired frequency spectrum.
    if (desiredRate != sampleRates.end()) {
        if (*desiredRate / AUDIO_RESAMPLER_DOWN_RATIO_MAX <= samplingRate) {
            updatedSamplingRate = *desiredRate;
            return NO_ERROR;
        }
    }
    // But if we have to up-sample from a lower sampling rate, that's OK.
    if (desiredRate != sampleRates.begin()) {
        uint32_t candidate = *(--desiredRate);
        if (candidate * AUDIO_RESAMPLER_UP_RATIO_MAX >= samplingRate) {
            updatedSamplingRate = candidate;
            return NO_ERROR;
        }
    }
    // leave updatedSamplingRate unmodified
    return BAD_VALUE;
}

status_t checkCompatibleChannelMask(const sp<AudioProfile> &audioProfile,
                                    audio_channel_mask_t channelMask,
                                    audio_channel_mask_t &updatedChannelMask,
                                    audio_port_type_t portType,
                                    audio_port_role_t portRole)
{
    const ChannelMaskSet channelMasks = audioProfile->getChannels();
    if (channelMasks.empty()) {
        updatedChannelMask = channelMask;
        return NO_ERROR;
    }
    const bool isRecordThread = portType == AUDIO_PORT_TYPE_MIX && portRole == AUDIO_PORT_ROLE_SINK;
    const bool isIndex = audio_channel_mask_get_representation(channelMask)
            == AUDIO_CHANNEL_REPRESENTATION_INDEX;
    const uint32_t channelCount = audio_channel_count_from_in_mask(channelMask);
    int bestMatch = 0;
    for (const auto &supported : channelMasks) {
        if (supported == channelMask) {
            // Exact matches always taken.
            updatedChannelMask = channelMask;
            return NO_ERROR;
        }

        // AUDIO_CHANNEL_NONE (value: 0) is used for dynamic channel support
        if (isRecordThread && supported != AUDIO_CHANNEL_NONE) {
            // Approximate (best) match:
            // The match score measures how well the supported channel mask matches the
            // desired mask, where increasing-is-better.
            //
            // TODO: Some tweaks may be needed.
            // Should be a static function of the data processing library.
            //
            // In priority:
            // match score = 1000 if legacy channel conversion equivalent (always prefer this)
            // OR
            // match score += 100 if the channel mask representations match
            // match score += number of channels matched.
            // match score += 100 if the channel mask representations DO NOT match
            //   but the profile has positional channel mask and less than 2 channels.
            //   This is for audio HAL convention to not list index masks for less than 2 channels
            //
            // If there are no matched channels, the mask may still be accepted
            // but the playback or record will be silent.
            const bool isSupportedIndex = (audio_channel_mask_get_representation(supported)
                    == AUDIO_CHANNEL_REPRESENTATION_INDEX);
            const uint32_t supportedChannelCount = audio_channel_count_from_in_mask(supported);
            int match;
            if (isIndex && isSupportedIndex) {
                // index equivalence
                match = 100 + __builtin_popcount(
                        audio_channel_mask_get_bits(channelMask)
                            & audio_channel_mask_get_bits(supported));
            } else if (isIndex && !isSupportedIndex) {
                const uint32_t equivalentBits = (1 << supportedChannelCount) - 1 ;
                match = __builtin_popcount(
                        audio_channel_mask_get_bits(channelMask) & equivalentBits);
                if (supportedChannelCount <= FCC_2) {
                    match += 100;
                }
            } else if (!isIndex && isSupportedIndex) {
                const uint32_t equivalentBits = (1 << channelCount) - 1;
                match = __builtin_popcount(
                        equivalentBits & audio_channel_mask_get_bits(supported));
            } else {
                // positional equivalence
                match = 100 + __builtin_popcount(
                        audio_channel_mask_get_bits(channelMask)
                            & audio_channel_mask_get_bits(supported));
                switch (supported) {
                case AUDIO_CHANNEL_IN_FRONT_BACK:
                case AUDIO_CHANNEL_IN_STEREO:
                    if (channelMask == AUDIO_CHANNEL_IN_MONO) {
                        match = 1000;
                    }
                    break;
                case AUDIO_CHANNEL_IN_MONO:
                    if (channelMask == AUDIO_CHANNEL_IN_FRONT_BACK
                            || channelMask == AUDIO_CHANNEL_IN_STEREO) {
                        match = 1000;
                    }
                    break;
                default:
                    break;
                }
            }
            if (match > bestMatch) {
                bestMatch = match;
                updatedChannelMask = supported;
            }
        }
    }
    return bestMatch > 0 ? NO_ERROR : BAD_VALUE;
}

status_t checkExactProfile(const AudioProfileVector& audioProfileVector,
                           const uint32_t samplingRate,
                           audio_channel_mask_t channelMask,
                           audio_format_t format)
{
    if (audioProfileVector.empty()) {
        return NO_ERROR;
    }

    for (const auto& profile : audioProfileVector) {
        if (checkExact(profile, samplingRate, channelMask, format) == NO_ERROR) {
            return NO_ERROR;
        }
    }
    return BAD_VALUE;
}

status_t checkCompatibleProfile(const AudioProfileVector &audioProfileVector,
                                uint32_t &samplingRate,
                                audio_channel_mask_t &channelMask,
                                audio_format_t &format,
                                audio_port_type_t portType,
                                audio_port_role_t portRole)
{
    if (audioProfileVector.empty()) {
        return NO_ERROR;
    }

    const bool checkInexact = // when port is input and format is linear pcm
            portType == AUDIO_PORT_TYPE_MIX && portRole == AUDIO_PORT_ROLE_SINK
            && audio_is_linear_pcm(format);

    // iterate from best format to worst format (reverse order)
    for (ssize_t i = audioProfileVector.size() - 1; i >= 0 ; --i) {
        const sp<AudioProfile> profile = audioProfileVector.at(i);
        audio_format_t formatToCompare = profile->getFormat();
        if (formatToCompare == format ||
                (checkInexact
                        && formatToCompare != AUDIO_FORMAT_DEFAULT
                        && audio_is_linear_pcm(formatToCompare))) {
            // Compatible profile has been found, checks if this profile has compatible
            // rate and channels as well
            audio_channel_mask_t updatedChannels;
            uint32_t updatedRate;
            if (checkCompatibleChannelMask(profile, channelMask, updatedChannels,
                                           portType, portRole) == NO_ERROR &&
                    checkCompatibleSamplingRate(profile, samplingRate, updatedRate) == NO_ERROR) {
                // for inexact checks we take the first linear pcm format due to sorting.
                format = formatToCompare;
                channelMask = updatedChannels;
                samplingRate = updatedRate;
                return NO_ERROR;
            }
        }
    }
    return BAD_VALUE;
}

// Returns an intersection between two possibly unsorted vectors and the contents of 'order'.
// The result is ordered according to 'order'.
template<typename T, typename Order>
std::vector<typename T::value_type> intersectFilterAndOrder(
        const T& input1, const T& input2, const Order& order)
{
    std::set<typename T::value_type> set1{input1.begin(), input1.end()};
    std::set<typename T::value_type> set2{input2.begin(), input2.end()};
    std::set<typename T::value_type> common;
    std::set_intersection(set1.begin(), set1.end(), set2.begin(), set2.end(),
            std::inserter(common, common.begin()));
    std::vector<typename T::value_type> result;
    for (const auto& e : order) {
        if (common.find(e) != common.end()) result.push_back(e);
    }
    return result;
}

// Intersect two possibly unsorted vectors, return common elements according to 'comp' ordering.
// 'comp' is a comparator function.
template<typename T, typename Compare>
std::vector<typename T::value_type> intersectAndOrder(
        const T& input1, const T& input2, Compare comp)
{
    std::set<typename T::value_type, Compare> set1{input1.begin(), input1.end(), comp};
    std::set<typename T::value_type, Compare> set2{input2.begin(), input2.end(), comp};
    std::vector<typename T::value_type> result;
    std::set_intersection(set1.begin(), set1.end(), set2.begin(), set2.end(),
            std::back_inserter(result), comp);
    return result;
}

status_t findBestMatchingOutputConfig(
        const AudioProfileVector &audioProfileVector,
        const AudioProfileVector &outputProfileVector,
        const std::vector<audio_format_t> &preferredFormatVector, // order: most pref -> least pref
        const std::vector<audio_channel_mask_t> &preferredOutputChannelVector,
        bool preferHigherSamplingRates,
        audio_config_base &bestOutputConfig)
{
    auto formats = intersectFilterAndOrder(audioProfileVector.getSupportedFormats(),
            outputProfileVector.getSupportedFormats(), preferredFormatVector);
    // Pick the best compatible profile.
    for (const auto& f : formats) {
        sp<AudioProfile> inputProfile = audioProfileVector.getFirstValidProfileFor(f);
        sp<AudioProfile> outputProfile = outputProfileVector.getFirstValidProfileFor(f);
        if (inputProfile == nullptr || outputProfile == nullptr) {
            continue;
        }
        auto channels = intersectFilterAndOrder(asOutMask(inputProfile->getChannels()),
                outputProfile->getChannels(), preferredOutputChannelVector);
        if (channels.empty()) {
            continue;
        }
        auto sampleRates = preferHigherSamplingRates ?
                intersectAndOrder(inputProfile->getSampleRates(), outputProfile->getSampleRates(),
                        std::greater<typename SampleRateSet::value_type>()) :
                intersectAndOrder(inputProfile->getSampleRates(), outputProfile->getSampleRates(),
                        std::less<typename SampleRateSet::value_type>());
        if (sampleRates.empty()) {
            continue;
        }
        ALOGD("%s() found channel mask %#x and sample rate %d for format %#x.",
                __func__, *channels.begin(), *sampleRates.begin(), f);
        bestOutputConfig.format = f;
        bestOutputConfig.sample_rate = *sampleRates.begin();
        bestOutputConfig.channel_mask = *channels.begin();
        return NO_ERROR;
    }
    return BAD_VALUE;
}

} // namespace android
