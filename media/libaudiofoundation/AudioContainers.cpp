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

#include <sstream>
#include <string>

#include <media/AudioContainers.h>

namespace android {

const DeviceTypeSet& getAudioDeviceOutAllSet() {
    static const DeviceTypeSet audioDeviceOutAllSet = DeviceTypeSet(
            std::begin(AUDIO_DEVICE_OUT_ALL_ARRAY),
            std::end(AUDIO_DEVICE_OUT_ALL_ARRAY));
    return audioDeviceOutAllSet;
}

const DeviceTypeSet& getAudioDeviceOutAllA2dpSet() {
    static const DeviceTypeSet audioDeviceOutAllA2dpSet = DeviceTypeSet(
            std::begin(AUDIO_DEVICE_OUT_ALL_A2DP_ARRAY),
            std::end(AUDIO_DEVICE_OUT_ALL_A2DP_ARRAY));
    return audioDeviceOutAllA2dpSet;
}

const DeviceTypeSet& getAudioDeviceOutAllScoSet() {
    static const DeviceTypeSet audioDeviceOutAllScoSet = DeviceTypeSet(
            std::begin(AUDIO_DEVICE_OUT_ALL_SCO_ARRAY),
            std::end(AUDIO_DEVICE_OUT_ALL_SCO_ARRAY));
    return audioDeviceOutAllScoSet;
}

const DeviceTypeSet& getAudioDeviceOutAllUsbSet() {
    static const DeviceTypeSet audioDeviceOutAllUsbSet = DeviceTypeSet(
            std::begin(AUDIO_DEVICE_OUT_ALL_USB_ARRAY),
            std::end(AUDIO_DEVICE_OUT_ALL_USB_ARRAY));
    return audioDeviceOutAllUsbSet;
}

const DeviceTypeSet& getAudioDeviceInAllSet() {
    static const DeviceTypeSet audioDeviceInAllSet = DeviceTypeSet(
            std::begin(AUDIO_DEVICE_IN_ALL_ARRAY),
            std::end(AUDIO_DEVICE_IN_ALL_ARRAY));
    return audioDeviceInAllSet;
}

const DeviceTypeSet& getAudioDeviceInAllUsbSet() {
    static const DeviceTypeSet audioDeviceInAllUsbSet = DeviceTypeSet(
            std::begin(AUDIO_DEVICE_IN_ALL_USB_ARRAY),
            std::end(AUDIO_DEVICE_IN_ALL_USB_ARRAY));
    return audioDeviceInAllUsbSet;
}

const DeviceTypeSet& getAudioDeviceOutAllBleSet() {
    static const DeviceTypeSet audioDeviceOutAllBleSet = DeviceTypeSet(
            std::begin(AUDIO_DEVICE_OUT_ALL_BLE_ARRAY),
            std::end(AUDIO_DEVICE_OUT_ALL_BLE_ARRAY));
    return audioDeviceOutAllBleSet;
}

const DeviceTypeSet& getAudioDeviceOutLeAudioUnicastSet() {
    static const DeviceTypeSet audioDeviceOutLeAudioUnicastSet = DeviceTypeSet(
            std::begin(AUDIO_DEVICE_OUT_BLE_UNICAST_ARRAY),
            std::end(AUDIO_DEVICE_OUT_BLE_UNICAST_ARRAY));
    return audioDeviceOutLeAudioUnicastSet;
}

const DeviceTypeSet& getAudioDeviceOutLeAudioBroadcastSet() {
    static const DeviceTypeSet audioDeviceOutLeAudioUnicastSet = DeviceTypeSet(
            std::begin(AUDIO_DEVICE_OUT_BLE_BROADCAST_ARRAY),
            std::end(AUDIO_DEVICE_OUT_BLE_BROADCAST_ARRAY));
    return audioDeviceOutLeAudioUnicastSet;
}

std::string deviceTypesToString(const DeviceTypeSet &deviceTypes) {
    if (deviceTypes.empty()) {
        return "Empty device types";
    }
    std::stringstream ss;
    for (auto it = deviceTypes.begin(); it != deviceTypes.end(); ++it) {
        if (it != deviceTypes.begin()) {
            ss << ", ";
        }
        const char* strType = audio_device_to_string(*it);
        if (strlen(strType) != 0) {
            ss << strType;
        } else {
            ss << "unknown type:0x" << std::hex << *it;
        }
    }
    return ss.str();
}

bool deviceTypesToString(const DeviceTypeSet &deviceTypes, std::string &str) {
    str = deviceTypesToString(deviceTypes);
    return true;
}

std::string dumpDeviceTypes(const DeviceTypeSet &deviceTypes) {
    std::stringstream ss;
    for (auto it = deviceTypes.begin(); it != deviceTypes.end(); ++it) {
        if (it != deviceTypes.begin()) {
            ss << ", ";
        }
        ss << "0x" << std::hex << (*it);
    }
    return ss.str();
}

std::string dumpMixerBehaviors(const MixerBehaviorSet& mixerBehaviors) {
    std::stringstream ss;
    for (auto it = mixerBehaviors.begin(); it != mixerBehaviors.end(); ++it) {
        if (it != mixerBehaviors.begin()) {
            ss << ", ";
        }
        ss << (*it);
    }
    return ss.str();
}

AudioProfileAttributesMultimap createAudioProfilesAttrMap(audio_profile profiles[],
                                                          uint32_t first,
                                                          uint32_t last) {
    AudioProfileAttributesMultimap result;
    for (uint32_t i = first; i < last; ++i) {
        SampleRateSet sampleRates(profiles[i].sample_rates,
                                  profiles[i].sample_rates + profiles[i].num_sample_rates);
        ChannelMaskSet channelMasks(profiles[i].channel_masks,
                                    profiles[i].channel_masks + profiles[i].num_channel_masks);
        result.emplace(profiles[i].format, std::make_pair(sampleRates, channelMasks));
    }
    return result;
}

namespace {

void populateAudioProfile(audio_format_t format,
                          const ChannelMaskSet& channelMasks,
                          const SampleRateSet& samplingRates,
                          audio_profile* profile) {
    profile->format = format;
    profile->num_channel_masks = 0;
    for (auto it = channelMasks.begin();
         it != channelMasks.end() && profile->num_channel_masks < AUDIO_PORT_MAX_CHANNEL_MASKS;
         ++it) {
        profile->channel_masks[profile->num_channel_masks++] = *it;
    }
    profile->num_sample_rates = 0;
    for (auto it = samplingRates.begin();
         it != samplingRates.end() && profile->num_sample_rates < AUDIO_PORT_MAX_SAMPLING_RATES;
         ++it) {
        profile->sample_rates[profile->num_sample_rates++] = *it;
    }
}

} // namespace

void populateAudioProfiles(const AudioProfileAttributesMultimap& profileAttrs,
                           audio_format_t format,
                           ChannelMaskSet allChannelMasks,
                           SampleRateSet allSampleRates,
                           audio_profile audioProfiles[],
                           uint32_t* numAudioProfiles,
                           uint32_t maxAudioProfiles) {
    if (*numAudioProfiles >= maxAudioProfiles) {
        return;
    }

    const auto lower= profileAttrs.lower_bound(format);
    const auto upper = profileAttrs.upper_bound(format);
    SampleRateSet sampleRatesPresent;
    ChannelMaskSet channelMasksPresent;
    for (auto it = lower; it != upper && *numAudioProfiles < maxAudioProfiles; ++it) {
        SampleRateSet srs;
        std::set_intersection(it->second.first.begin(), it->second.first.end(),
                              allSampleRates.begin(), allSampleRates.end(),
                              std::inserter(srs, srs.begin()));
        if (srs.empty()) {
            continue;
        }
        ChannelMaskSet cms;
        std::set_intersection(it->second.second.begin(), it->second.second.end(),
                              allChannelMasks.begin(), allChannelMasks.end(),
                              std::inserter(cms, cms.begin()));
        if (cms.empty()) {
            continue;
        }
        sampleRatesPresent.insert(srs.begin(), srs.end());
        channelMasksPresent.insert(cms.begin(), cms.end());
        populateAudioProfile(it->first, cms, srs,
                             &audioProfiles[(*numAudioProfiles)++]);
    }
    if (*numAudioProfiles >= maxAudioProfiles) {
        ALOGW("%s, too many audio profiles", __func__);
        return;
    }

    SampleRateSet srs;
    std::set_difference(allSampleRates.begin(), allSampleRates.end(),
                        sampleRatesPresent.begin(), sampleRatesPresent.end(),
                        std::inserter(srs, srs.begin()));
    if (!srs.empty()) {
        populateAudioProfile(format, allChannelMasks, srs,
                             &audioProfiles[(*numAudioProfiles)++]);
    }
    if (*numAudioProfiles >= maxAudioProfiles) {
        ALOGW("%s, too many audio profiles", __func__);
        return;
    }
    ChannelMaskSet cms;
    std::set_difference(allChannelMasks.begin(), allChannelMasks.end(),
                        channelMasksPresent.begin(), channelMasksPresent.end(),
                        std::inserter(cms, cms.begin()));
    if (!cms.empty()) {
        populateAudioProfile(format, cms, allSampleRates,
                             &audioProfiles[(*numAudioProfiles)++]);
    }

}

} // namespace android
