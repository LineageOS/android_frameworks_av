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

#include <algorithm>
#include <functional>
#include <iterator>
#include <map>
#include <set>
#include <vector>

#include <media/TypeConverter.h>
#include <system/audio.h>

namespace android {

using ChannelMaskSet = std::set<audio_channel_mask_t>;
using DeviceTypeSet = std::set<audio_devices_t>;
using FormatSet = std::set<audio_format_t>;
using SampleRateSet = std::set<uint32_t>;
using MixerBehaviorSet = std::set<audio_mixer_behavior_t>;

using FormatVector = std::vector<audio_format_t>;
using AudioProfileAttributesMultimap =
        std::multimap<audio_format_t, std::pair<SampleRateSet, ChannelMaskSet>>;

const DeviceTypeSet& getAudioDeviceOutAllSet();
const DeviceTypeSet& getAudioDeviceOutAllA2dpSet();
const DeviceTypeSet& getAudioDeviceOutAllScoSet();
const DeviceTypeSet& getAudioDeviceOutAllUsbSet();
const DeviceTypeSet& getAudioDeviceInAllSet();
const DeviceTypeSet& getAudioDeviceInAllUsbSet();
const DeviceTypeSet& getAudioDeviceOutAllBleSet();
const DeviceTypeSet& getAudioDeviceOutLeAudioUnicastSet();
const DeviceTypeSet& getAudioDeviceOutLeAudioBroadcastSet();

template<typename T>
static std::vector<T> Intersection(const std::set<T>& a, const std::set<T>& b) {
    std::vector<T> intersection;
    std::set_intersection(a.begin(), a.end(),
                          b.begin(), b.end(),
                          std::back_inserter(intersection));
    return intersection;
}

template<typename T>
static std::set<T> SetIntersection(const std::set<T>& a, const std::set<T> b) {
    std::set<T> intersection;
    std::set_intersection(a.begin(), a.end(),
                          b.begin(), b.end(),
                          std::inserter(intersection, intersection.begin()));
    return intersection;
}

static inline ChannelMaskSet asInMask(const ChannelMaskSet& channelMasks) {
    ChannelMaskSet inMaskSet;
    for (const auto &channel : channelMasks) {
        if (audio_channel_mask_out_to_in(channel) != AUDIO_CHANNEL_INVALID) {
            inMaskSet.insert(audio_channel_mask_out_to_in(channel));
        } else if (audio_channel_mask_get_representation(channel)
                    == AUDIO_CHANNEL_REPRESENTATION_INDEX) {
            inMaskSet.insert(channel);
        }
    }
    return inMaskSet;
}

static inline ChannelMaskSet asOutMask(const ChannelMaskSet& channelMasks) {
    ChannelMaskSet outMaskSet;
    for (const auto &channel : channelMasks) {
        if (audio_channel_mask_in_to_out(channel) != AUDIO_CHANNEL_INVALID) {
            outMaskSet.insert(audio_channel_mask_in_to_out(channel));
        } else if (audio_channel_mask_get_representation(channel)
                    == AUDIO_CHANNEL_REPRESENTATION_INDEX) {
            outMaskSet.insert(channel);
        }
    }
    return outMaskSet;
}

static inline bool isSingleDeviceType(const DeviceTypeSet& deviceTypes,
                                      audio_devices_t deviceType) {
    return deviceTypes.size() == 1 && *(deviceTypes.begin()) == deviceType;
}

typedef bool (*DeviceTypeUnaryPredicate)(audio_devices_t);
static inline bool isSingleDeviceType(const DeviceTypeSet& deviceTypes,
                                      DeviceTypeUnaryPredicate p) {
    return deviceTypes.size() == 1 && p(*(deviceTypes.begin()));
}

static inline bool areAllOfSameDeviceType(const DeviceTypeSet& deviceTypes,
                                          std::function<bool(audio_devices_t)> p) {
    return std::all_of(deviceTypes.begin(), deviceTypes.end(), p);
}

static inline void resetDeviceTypes(DeviceTypeSet& deviceTypes, audio_devices_t typeToAdd) {
    deviceTypes.clear();
    deviceTypes.insert(typeToAdd);
}

// FIXME: This is temporary helper function. Remove this when getting rid of all
//  bit mask usages of audio device types.
static inline audio_devices_t deviceTypesToBitMask(const DeviceTypeSet& deviceTypes) {
    audio_devices_t types = AUDIO_DEVICE_NONE;
    for (auto deviceType : deviceTypes) {
        types = static_cast<audio_devices_t>(types | deviceType);
    }
    return types;
}

std::string deviceTypesToString(const DeviceTypeSet& deviceTypes);

bool deviceTypesToString(const DeviceTypeSet& deviceTypes, std::string &str);

std::string dumpDeviceTypes(const DeviceTypeSet& deviceTypes);

std::string dumpMixerBehaviors(const MixerBehaviorSet& mixerBehaviors);

/**
 * Return human readable string for device types.
 */
inline std::string toString(const DeviceTypeSet& deviceTypes) {
    return deviceTypesToString(deviceTypes);
}

/**
 * Create audio profile attributes map by given audio profile array from the range of [first, last).
 *
 * @param profiles the array of audio profiles.
 * @param first the first index of the profile.
 * @param last the last index of the profile.
 * @return a multipmap of audio format to pair of corresponding sample rates and channel masks set.
 */
AudioProfileAttributesMultimap createAudioProfilesAttrMap(audio_profile profiles[],
                                                          uint32_t first,
                                                          uint32_t last);

/**
 * Populate audio profiles according to given profile attributes, format, channel masks and
 * sample rates.
 *
 * The function will first go over all pairs of channel masks and sample rates that are present in
 * the profile attributes of the given map. Note that the channel masks and the sample rates that
 * are not present in the collections of all valid channel masks and all valid sample rates will be
 * excluded. After that, if there are channel masks and sample rates that present in the all values
 * collection but not in profile attributes, they will also be place in a new audio profile in the
 * profile array.
 *
 * Note that if the resulting index of the audio profile exceeds the maximum, no new audio profiles
 * will be placed in the array.
 *
 * @param profileAttrs a multimap that contains format and its corresponding channel masks and
 *                     sample rates.
 * @param format the targeted audio format.
 * @param allChannelMasks all valid channel masks for the format.
 * @param allSampleRates all valid sample rates for the format.
 * @param audioProfiles the audio profile array.
 * @param numAudioProfiles the start index to put audio profile in the array. The value will be
 *                         updated if there is new audio profile placed.
 * @param maxAudioProfiles the maximum number of audio profile.
 */
void populateAudioProfiles(const AudioProfileAttributesMultimap& profileAttrs,
                           audio_format_t format,
                           ChannelMaskSet allChannelMasks,
                           SampleRateSet allSampleRates,
                           audio_profile audioProfiles[],
                           uint32_t* numAudioProfiles,
                           uint32_t maxAudioProfiles = AUDIO_PORT_MAX_AUDIO_PROFILES);


} // namespace android
