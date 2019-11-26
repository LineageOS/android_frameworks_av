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

#include <media/AudioContainers.h>
#include <system/audio.h>
#include <utils/RefBase.h>
#include <utils/String8.h>

#include "policy.h"

namespace android {

class AudioProfile : public virtual RefBase
{
public:
    static sp<AudioProfile> createFullDynamic();

    AudioProfile(audio_format_t format, audio_channel_mask_t channelMasks, uint32_t samplingRate);
    AudioProfile(audio_format_t format,
                 const ChannelMaskSet &channelMasks,
                 const SampleRateSet &samplingRateCollection);

    audio_format_t getFormat() const { return mFormat; }
    const ChannelMaskSet &getChannels() const { return mChannelMasks; }
    const SampleRateSet &getSampleRates() const { return mSamplingRates; }
    void setChannels(const ChannelMaskSet &channelMasks);
    void setSampleRates(const SampleRateSet &sampleRates);

    void clear();
    bool isValid() const { return hasValidFormat() && hasValidRates() && hasValidChannels(); }
    bool supportsChannels(audio_channel_mask_t channels) const
    {
        return mChannelMasks.count(channels) != 0;
    }
    bool supportsRate(uint32_t rate) const { return mSamplingRates.count(rate) != 0; }

    status_t checkExact(uint32_t rate, audio_channel_mask_t channels, audio_format_t format) const;
    status_t checkCompatibleChannelMask(audio_channel_mask_t channelMask,
                                        audio_channel_mask_t &updatedChannelMask,
                                        audio_port_type_t portType,
                                        audio_port_role_t portRole) const;
    status_t checkCompatibleSamplingRate(uint32_t samplingRate,
                                         uint32_t &updatedSamplingRate) const;

    bool hasValidFormat() const { return mFormat != AUDIO_FORMAT_DEFAULT; }
    bool hasValidRates() const { return !mSamplingRates.empty(); }
    bool hasValidChannels() const { return !mChannelMasks.empty(); }

    void setDynamicChannels(bool dynamic) { mIsDynamicChannels = dynamic; }
    bool isDynamicChannels() const { return mIsDynamicChannels; }

    void setDynamicRate(bool dynamic) { mIsDynamicRate = dynamic; }
    bool isDynamicRate() const { return mIsDynamicRate; }

    void setDynamicFormat(bool dynamic) { mIsDynamicFormat = dynamic; }
    bool isDynamicFormat() const { return mIsDynamicFormat; }

    bool isDynamic() { return mIsDynamicFormat || mIsDynamicChannels || mIsDynamicRate; }

    void dump(String8 *dst, int spaces) const;

private:
    String8  mName;
    audio_format_t mFormat;
    ChannelMaskSet mChannelMasks;
    SampleRateSet mSamplingRates;

    bool mIsDynamicFormat = false;
    bool mIsDynamicChannels = false;
    bool mIsDynamicRate = false;
};


class AudioProfileVector : public std::vector<sp<AudioProfile> >
{
public:
    ssize_t add(const sp<AudioProfile> &profile);
    // This API is intended to be used by the policy manager once retrieving capabilities
    // for a profile with dynamic format, rate and channels attributes
    ssize_t addProfileFromHal(const sp<AudioProfile> &profileToAdd);
    void appendProfiles(const AudioProfileVector& audioProfiles) {
        insert(end(), audioProfiles.begin(), audioProfiles.end());
    }

    status_t checkExactProfile(uint32_t samplingRate, audio_channel_mask_t channelMask,
                               audio_format_t format) const;
    status_t checkCompatibleProfile(uint32_t &samplingRate, audio_channel_mask_t &channelMask,
                                    audio_format_t &format,
                                    audio_port_type_t portType,
                                    audio_port_role_t portRole) const;
    void clearProfiles();
    // Assuming that this profile vector contains input profiles,
    // find the best matching config from 'outputProfiles', according to
    // the given preferences for audio formats and channel masks.
    // Note: std::vectors are used because specialized containers for formats
    //       and channels can be sorted and use their own ordering.
    status_t findBestMatchingOutputConfig(const AudioProfileVector& outputProfiles,
            const std::vector<audio_format_t>& preferredFormats, // order: most pref -> least pref
            const std::vector<audio_channel_mask_t>& preferredOutputChannels,
            bool preferHigherSamplingRates,
            audio_config_base *bestOutputConfig) const;

    sp<AudioProfile> getFirstValidProfile() const;
    sp<AudioProfile> getFirstValidProfileFor(audio_format_t format) const;
    bool hasValidProfile() const { return getFirstValidProfile() != 0; }

    FormatVector getSupportedFormats() const;
    bool hasDynamicChannelsFor(audio_format_t format) const;
    bool hasDynamicFormat() const { return getProfileFor(gDynamicFormat) != 0; }
    bool hasDynamicProfile() const;
    bool hasDynamicRateFor(audio_format_t format) const;

    // One audio profile will be added for each format supported by Audio HAL
    void setFormats(const FormatVector &formats);

    void dump(String8 *dst, int spaces) const;

private:
    sp<AudioProfile> getProfileFor(audio_format_t format) const;
    void setSampleRatesFor(const SampleRateSet &sampleRates, audio_format_t format);
    void setChannelsFor(const ChannelMaskSet &channelMasks, audio_format_t format);
};

bool operator == (const AudioProfile &left, const AudioProfile &right);

} // namespace android
