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

#include <string>
#include <vector>

#include <binder/Parcel.h>
#include <binder/Parcelable.h>
#include <media/AudioContainers.h>
#include <system/audio.h>
#include <utils/RefBase.h>

namespace android {

class AudioProfile final : public RefBase, public Parcelable
{
public:
    static sp<AudioProfile> createFullDynamic(audio_format_t dynamicFormat = AUDIO_FORMAT_DEFAULT);

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

    void dump(std::string *dst, int spaces) const;

    bool equals(const sp<AudioProfile>& other) const;

    status_t writeToParcel(Parcel* parcel) const override;
    status_t readFromParcel(const Parcel* parcel) override;

private:
    std::string  mName;
    audio_format_t mFormat; // The format for an audio profile should only be set when initialized.
    ChannelMaskSet mChannelMasks;
    SampleRateSet mSamplingRates;

    bool mIsDynamicFormat = false;
    bool mIsDynamicChannels = false;
    bool mIsDynamicRate = false;
};

class AudioProfileVector : public std::vector<sp<AudioProfile>>, public Parcelable
{
public:
    virtual ~AudioProfileVector() = default;

    virtual ssize_t add(const sp<AudioProfile> &profile);

    // If the profile is dynamic format and has valid format, it will be removed when doing
    // clearProfiles(). Otherwise, AudioProfile::clear() will be called.
    virtual void clearProfiles();

    sp<AudioProfile> getFirstValidProfile() const;
    sp<AudioProfile> getFirstValidProfileFor(audio_format_t format) const;
    bool hasValidProfile() const { return getFirstValidProfile() != 0; }

    FormatVector getSupportedFormats() const;
    bool hasDynamicChannelsFor(audio_format_t format) const;
    bool hasDynamicFormat() const;
    bool hasDynamicProfile() const;
    bool hasDynamicRateFor(audio_format_t format) const;

    virtual void dump(std::string *dst, int spaces) const;

    bool equals(const AudioProfileVector& other) const;

    status_t writeToParcel(Parcel* parcel) const override;
    status_t readFromParcel(const Parcel* parcel) override;
};

bool operator == (const AudioProfile &left, const AudioProfile &right);

} // namespace android
