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

#include <set>

#define LOG_TAG "AudioProfile"
//#define LOG_NDEBUG 0

#include <android-base/stringprintf.h>
#include <media/AudioContainers.h>
#include <media/AudioProfile.h>
#include <media/TypeConverter.h>
#include <utils/Errors.h>

namespace android {

bool operator == (const AudioProfile &left, const AudioProfile &right)
{
    return (left.getFormat() == right.getFormat()) &&
            (left.getChannels() == right.getChannels()) &&
            (left.getSampleRates() == right.getSampleRates());
}

// static
sp<AudioProfile> AudioProfile::createFullDynamic(audio_format_t dynamicFormat)
{
    AudioProfile* dynamicProfile = new AudioProfile(dynamicFormat,
            ChannelMaskSet(), SampleRateSet());
    dynamicProfile->setDynamicFormat(true);
    dynamicProfile->setDynamicChannels(true);
    dynamicProfile->setDynamicRate(true);
    return dynamicProfile;
}

AudioProfile::AudioProfile(audio_format_t format,
                           audio_channel_mask_t channelMasks,
                           uint32_t samplingRate) :
        mName(""),
        mFormat(format)
{
    mChannelMasks.insert(channelMasks);
    mSamplingRates.insert(samplingRate);
}

AudioProfile::AudioProfile(audio_format_t format,
                           const ChannelMaskSet &channelMasks,
                           const SampleRateSet &samplingRateCollection) :
        mName(""),
        mFormat(format),
        mChannelMasks(channelMasks),
        mSamplingRates(samplingRateCollection) {}

void AudioProfile::setChannels(const ChannelMaskSet &channelMasks)
{
    if (mIsDynamicChannels) {
        mChannelMasks = channelMasks;
    }
}

void AudioProfile::setSampleRates(const SampleRateSet &sampleRates)
{
    if (mIsDynamicRate) {
        mSamplingRates = sampleRates;
    }
}

void AudioProfile::clear()
{
    if (mIsDynamicChannels) {
        mChannelMasks.clear();
    }
    if (mIsDynamicRate) {
        mSamplingRates.clear();
    }
}

void AudioProfile::dump(std::string *dst, int spaces) const
{
    dst->append(base::StringPrintf("%s%s%s\n", mIsDynamicFormat ? "[dynamic format]" : "",
             mIsDynamicChannels ? "[dynamic channels]" : "",
             mIsDynamicRate ? "[dynamic rates]" : ""));
    if (mName.length() != 0) {
        dst->append(base::StringPrintf("%*s- name: %s\n", spaces, "", mName.c_str()));
    }
    std::string formatLiteral;
    if (FormatConverter::toString(mFormat, formatLiteral)) {
        dst->append(base::StringPrintf("%*s- format: %s\n", spaces, "", formatLiteral.c_str()));
    }
    if (!mSamplingRates.empty()) {
        dst->append(base::StringPrintf("%*s- sampling rates:", spaces, ""));
        for (auto it = mSamplingRates.begin(); it != mSamplingRates.end();) {
            dst->append(base::StringPrintf("%d", *it));
            dst->append(++it == mSamplingRates.end() ? "" : ", ");
        }
        dst->append("\n");
    }

    if (!mChannelMasks.empty()) {
        dst->append(base::StringPrintf("%*s- channel masks:", spaces, ""));
        for (auto it = mChannelMasks.begin(); it != mChannelMasks.end();) {
            dst->append(base::StringPrintf("0x%04x", *it));
            dst->append(++it == mChannelMasks.end() ? "" : ", ");
        }
        dst->append("\n");
    }
}

ssize_t AudioProfileVectorBase::add(const sp<AudioProfile> &profile)
{
    ssize_t index = size();
    push_back(profile);
    return index;
}

void AudioProfileVectorBase::clearProfiles()
{
    for (auto it = begin(); it != end();) {
        if ((*it)->isDynamicFormat() && (*it)->hasValidFormat()) {
            it = erase(it);
        } else {
            (*it)->clear();
            ++it;
        }
    }
}

sp<AudioProfile> AudioProfileVectorBase::getFirstValidProfile() const
{
    for (const auto &profile : *this) {
        if (profile->isValid()) {
            return profile;
        }
    }
    return nullptr;
}

sp<AudioProfile> AudioProfileVectorBase::getFirstValidProfileFor(audio_format_t format) const
{
    for (const auto &profile : *this) {
        if (profile->isValid() && profile->getFormat() == format) {
            return profile;
        }
    }
    return nullptr;
}

FormatVector AudioProfileVectorBase::getSupportedFormats() const
{
    FormatVector supportedFormats;
    for (const auto &profile : *this) {
        if (profile->hasValidFormat()) {
            supportedFormats.push_back(profile->getFormat());
        }
    }
    return supportedFormats;
}

bool AudioProfileVectorBase::hasDynamicChannelsFor(audio_format_t format) const
{
    for (const auto &profile : *this) {
        if (profile->getFormat() == format && profile->isDynamicChannels()) {
            return true;
        }
    }
    return false;
}

bool AudioProfileVectorBase::hasDynamicFormat() const
{
    for (const auto &profile : *this) {
        if (profile->isDynamicFormat()) {
            return true;
        }
    }
    return false;
}

bool AudioProfileVectorBase::hasDynamicProfile() const
{
    for (const auto &profile : *this) {
        if (profile->isDynamic()) {
            return true;
        }
    }
    return false;
}

bool AudioProfileVectorBase::hasDynamicRateFor(audio_format_t format) const
{
    for (const auto &profile : *this) {
        if (profile->getFormat() == format && profile->isDynamicRate()) {
            return true;
        }
    }
    return false;
}

void AudioProfileVectorBase::dump(std::string *dst, int spaces) const
{
    dst->append(base::StringPrintf("%*s- Profiles:\n", spaces, ""));
    for (size_t i = 0; i < size(); i++) {
        dst->append(base::StringPrintf("%*sProfile %zu:", spaces + 4, "", i));
        std::string profileStr;
        at(i)->dump(&profileStr, spaces + 8);
        dst->append(profileStr);
    }
}

} // namespace android
