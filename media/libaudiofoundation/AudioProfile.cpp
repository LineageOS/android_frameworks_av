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

bool AudioProfile::equals(const sp<AudioProfile>& other) const
{
    return other != nullptr &&
           mName.compare(other->mName) == 0 &&
           mFormat == other->getFormat() &&
           mChannelMasks == other->getChannels() &&
           mSamplingRates == other->getSampleRates() &&
           mIsDynamicFormat == other->isDynamicFormat() &&
           mIsDynamicChannels == other->isDynamicChannels() &&
           mIsDynamicRate == other->isDynamicRate();
}

status_t AudioProfile::writeToParcel(Parcel *parcel) const
{
    status_t status = NO_ERROR;
    if ((status = parcel->writeUtf8AsUtf16(mName)) != NO_ERROR) return status;
    if ((status = parcel->writeUint32(mFormat)) != NO_ERROR) return status;
    std::vector<int> values(mChannelMasks.begin(), mChannelMasks.end());
    if ((status = parcel->writeInt32Vector(values)) != NO_ERROR) return status;
    values.clear();
    values.assign(mSamplingRates.begin(), mSamplingRates.end());
    if ((status = parcel->writeInt32Vector(values)) != NO_ERROR) return status;
    if ((status = parcel->writeBool(mIsDynamicFormat)) != NO_ERROR) return status;
    if ((status = parcel->writeBool(mIsDynamicChannels)) != NO_ERROR) return status;
    if ((status = parcel->writeBool(mIsDynamicRate)) != NO_ERROR) return status;
    return status;
}

status_t AudioProfile::readFromParcel(const Parcel *parcel)
{
    status_t status = NO_ERROR;
    if ((status = parcel->readUtf8FromUtf16(&mName)) != NO_ERROR) return status;
    static_assert(sizeof(mFormat) == sizeof(uint32_t));
    if ((status = parcel->readUint32(reinterpret_cast<uint32_t*>(&mFormat))) != NO_ERROR) {
        return status;
    }
    std::vector<int> values;
    if ((status = parcel->readInt32Vector(&values)) != NO_ERROR) return status;
    mChannelMasks.clear();
    mChannelMasks.insert(values.begin(), values.end());
    values.clear();
    if ((status = parcel->readInt32Vector(&values)) != NO_ERROR) return status;
    mSamplingRates.clear();
    mSamplingRates.insert(values.begin(), values.end());
    if ((status = parcel->readBool(&mIsDynamicFormat)) != NO_ERROR) return status;
    if ((status = parcel->readBool(&mIsDynamicChannels)) != NO_ERROR) return status;
    if ((status = parcel->readBool(&mIsDynamicRate)) != NO_ERROR) return status;
    return status;
}

ssize_t AudioProfileVector::add(const sp<AudioProfile> &profile)
{
    ssize_t index = size();
    push_back(profile);
    return index;
}

void AudioProfileVector::clearProfiles()
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

sp<AudioProfile> AudioProfileVector::getFirstValidProfile() const
{
    for (const auto &profile : *this) {
        if (profile->isValid()) {
            return profile;
        }
    }
    return nullptr;
}

sp<AudioProfile> AudioProfileVector::getFirstValidProfileFor(audio_format_t format) const
{
    for (const auto &profile : *this) {
        if (profile->isValid() && profile->getFormat() == format) {
            return profile;
        }
    }
    return nullptr;
}

FormatVector AudioProfileVector::getSupportedFormats() const
{
    FormatVector supportedFormats;
    for (const auto &profile : *this) {
        if (profile->hasValidFormat()) {
            supportedFormats.push_back(profile->getFormat());
        }
    }
    return supportedFormats;
}

bool AudioProfileVector::hasDynamicChannelsFor(audio_format_t format) const
{
    for (const auto &profile : *this) {
        if (profile->getFormat() == format && profile->isDynamicChannels()) {
            return true;
        }
    }
    return false;
}

bool AudioProfileVector::hasDynamicFormat() const
{
    for (const auto &profile : *this) {
        if (profile->isDynamicFormat()) {
            return true;
        }
    }
    return false;
}

bool AudioProfileVector::hasDynamicProfile() const
{
    for (const auto &profile : *this) {
        if (profile->isDynamic()) {
            return true;
        }
    }
    return false;
}

bool AudioProfileVector::hasDynamicRateFor(audio_format_t format) const
{
    for (const auto &profile : *this) {
        if (profile->getFormat() == format && profile->isDynamicRate()) {
            return true;
        }
    }
    return false;
}

void AudioProfileVector::dump(std::string *dst, int spaces) const
{
    dst->append(base::StringPrintf("%*s- Profiles:\n", spaces, ""));
    for (size_t i = 0; i < size(); i++) {
        dst->append(base::StringPrintf("%*sProfile %zu:", spaces + 4, "", i));
        std::string profileStr;
        at(i)->dump(&profileStr, spaces + 8);
        dst->append(profileStr);
    }
}

status_t AudioProfileVector::writeToParcel(Parcel *parcel) const
{
    status_t status = NO_ERROR;
    if ((status = parcel->writeVectorSize(*this)) != NO_ERROR) return status;
    for (const auto &audioProfile : *this) {
        if ((status = parcel->writeParcelable(*audioProfile)) != NO_ERROR) {
            break;
        }
    }
    return status;
}

status_t AudioProfileVector::readFromParcel(const Parcel *parcel)
{
    status_t status = NO_ERROR;
    this->clear();
    if ((status = parcel->resizeOutVector(this)) != NO_ERROR) return status;
    for (size_t i = 0; i < this->size(); ++i) {
        this->at(i) = new AudioProfile(AUDIO_FORMAT_DEFAULT, AUDIO_CHANNEL_NONE, 0 /*sampleRate*/);
        if ((status = parcel->readParcelable(this->at(i).get())) != NO_ERROR) {
            this->clear();
            break;
        }
    }
    return status;
}

bool AudioProfileVector::equals(const AudioProfileVector& other) const
{
    return std::equal(begin(), end(), other.begin(), other.end(),
                      [](const sp<AudioProfile>& left, const sp<AudioProfile>& right) {
                          return left->equals(right);
                      });
}

} // namespace android
