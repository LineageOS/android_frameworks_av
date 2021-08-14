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

#define LOG_TAG "AudioGain"
//#define LOG_NDEBUG 0

//#define VERY_VERBOSE_LOGGING
#ifdef VERY_VERBOSE_LOGGING
#define ALOGVV ALOGV
#else
#define ALOGVV(a...) do { } while(0)
#endif

#include <algorithm>

#include <android-base/stringprintf.h>
#include <media/AudioGain.h>
#include <utils/Log.h>

#include <math.h>

namespace android {

AudioGain::AudioGain(int index, bool useInChannelMask)
{
    mIndex = index;
    mUseInChannelMask = useInChannelMask;
    memset(&mGain, 0, sizeof(struct audio_gain));
}

void AudioGain::getDefaultConfig(struct audio_gain_config *config)
{
    config->index = mIndex;
    config->mode = mGain.mode;
    config->channel_mask = mGain.channel_mask;
    if ((mGain.mode & AUDIO_GAIN_MODE_JOINT) == AUDIO_GAIN_MODE_JOINT) {
        config->values[0] = mGain.default_value;
    } else {
        uint32_t numValues;
        if (mUseInChannelMask) {
            numValues = audio_channel_count_from_in_mask(mGain.channel_mask);
        } else {
            numValues = audio_channel_count_from_out_mask(mGain.channel_mask);
        }
        for (size_t i = 0; i < numValues; i++) {
            config->values[i] = mGain.default_value;
        }
    }
    if ((mGain.mode & AUDIO_GAIN_MODE_RAMP) == AUDIO_GAIN_MODE_RAMP) {
        config->ramp_duration_ms = mGain.min_ramp_ms;
    }
}

status_t AudioGain::checkConfig(const struct audio_gain_config *config)
{
    if ((config->mode & ~mGain.mode) != 0) {
        return BAD_VALUE;
    }
    if ((config->mode & AUDIO_GAIN_MODE_JOINT) == AUDIO_GAIN_MODE_JOINT) {
        if ((config->values[0] < mGain.min_value) ||
                    (config->values[0] > mGain.max_value)) {
            return BAD_VALUE;
        }
    } else {
        if ((config->channel_mask & ~mGain.channel_mask) != 0) {
            return BAD_VALUE;
        }
        uint32_t numValues;
        if (mUseInChannelMask) {
            numValues = audio_channel_count_from_in_mask(config->channel_mask);
        } else {
            numValues = audio_channel_count_from_out_mask(config->channel_mask);
        }
        for (size_t i = 0; i < numValues; i++) {
            if ((config->values[i] < mGain.min_value) ||
                    (config->values[i] > mGain.max_value)) {
                return BAD_VALUE;
            }
        }
    }
    if ((config->mode & AUDIO_GAIN_MODE_RAMP) == AUDIO_GAIN_MODE_RAMP) {
        if ((config->ramp_duration_ms < mGain.min_ramp_ms) ||
                    (config->ramp_duration_ms > mGain.max_ramp_ms)) {
            return BAD_VALUE;
        }
    }
    return NO_ERROR;
}

void AudioGain::dump(std::string *dst, int spaces, int index) const
{
    dst->append(base::StringPrintf("%*sGain %d:\n", spaces, "", index+1));
    dst->append(base::StringPrintf("%*s- mode: %08x\n", spaces, "", mGain.mode));
    dst->append(base::StringPrintf("%*s- channel_mask: %08x\n", spaces, "", mGain.channel_mask));
    dst->append(base::StringPrintf("%*s- min_value: %d mB\n", spaces, "", mGain.min_value));
    dst->append(base::StringPrintf("%*s- max_value: %d mB\n", spaces, "", mGain.max_value));
    dst->append(base::StringPrintf("%*s- default_value: %d mB\n", spaces, "", mGain.default_value));
    dst->append(base::StringPrintf("%*s- step_value: %d mB\n", spaces, "", mGain.step_value));
    dst->append(base::StringPrintf("%*s- min_ramp_ms: %d ms\n", spaces, "", mGain.min_ramp_ms));
    dst->append(base::StringPrintf("%*s- max_ramp_ms: %d ms\n", spaces, "", mGain.max_ramp_ms));
}

bool AudioGain::equals(const sp<AudioGain>& other) const
{
    return other != nullptr &&
           mUseInChannelMask == other->mUseInChannelMask &&
           mUseForVolume == other->mUseForVolume &&
           // Compare audio gain
           mGain.mode == other->mGain.mode &&
           mGain.channel_mask == other->mGain.channel_mask &&
           mGain.min_value == other->mGain.min_value &&
           mGain.max_value == other->mGain.max_value &&
           mGain.default_value == other->mGain.default_value &&
           mGain.step_value == other->mGain.step_value &&
           mGain.min_ramp_ms == other->mGain.min_ramp_ms &&
           mGain.max_ramp_ms == other->mGain.max_ramp_ms;
}

status_t AudioGain::writeToParcel(android::Parcel *parcel) const {
    media::AudioGain parcelable;
    return writeToParcelable(&parcelable)
        ?: parcelable.writeToParcel(parcel);
}

status_t AudioGain::writeToParcelable(media::AudioGain* parcelable) const {
    parcelable->index = VALUE_OR_RETURN_STATUS(convertIntegral<int32_t>(mIndex));
    parcelable->useInChannelMask = mUseInChannelMask;
    parcelable->useForVolume = mUseForVolume;
    parcelable->mode = VALUE_OR_RETURN_STATUS(
            legacy2aidl_audio_gain_mode_t_int32_t_mask(mGain.mode));
    parcelable->channelMask = VALUE_OR_RETURN_STATUS(
            legacy2aidl_audio_channel_mask_t_int32_t(mGain.channel_mask));
    parcelable->minValue = VALUE_OR_RETURN_STATUS(convertIntegral<int32_t>(mGain.min_value));
    parcelable->maxValue = VALUE_OR_RETURN_STATUS(convertIntegral<int32_t>(mGain.max_value));
    parcelable->defaultValue = VALUE_OR_RETURN_STATUS(
            convertIntegral<int32_t>(mGain.default_value));
    parcelable->stepValue = VALUE_OR_RETURN_STATUS(convertIntegral<int32_t>(mGain.step_value));
    parcelable->minRampMs = VALUE_OR_RETURN_STATUS(convertIntegral<int32_t>(mGain.min_ramp_ms));
    parcelable->maxRampMs = VALUE_OR_RETURN_STATUS(convertIntegral<int32_t>(mGain.max_ramp_ms));
    return OK;
}

status_t AudioGain::readFromParcel(const android::Parcel *parcel) {
    media::AudioGain parcelable;
    return parcelable.readFromParcel(parcel)
        ?: readFromParcelable(parcelable);
}

status_t AudioGain::readFromParcelable(const media::AudioGain& parcelable) {
    mIndex = VALUE_OR_RETURN_STATUS(convertIntegral<int>(parcelable.index));
    mUseInChannelMask = parcelable.useInChannelMask;
    mUseForVolume = parcelable.useForVolume;
    mGain.mode = VALUE_OR_RETURN_STATUS(
            aidl2legacy_int32_t_audio_gain_mode_t_mask(parcelable.mode));
    mGain.channel_mask = VALUE_OR_RETURN_STATUS(
            aidl2legacy_int32_t_audio_channel_mask_t(parcelable.channelMask));
    mGain.min_value = VALUE_OR_RETURN_STATUS(convertIntegral<int>(parcelable.minValue));
    mGain.max_value = VALUE_OR_RETURN_STATUS(convertIntegral<int>(parcelable.maxValue));
    mGain.default_value = VALUE_OR_RETURN_STATUS(convertIntegral<int>(parcelable.defaultValue));
    mGain.step_value = VALUE_OR_RETURN_STATUS(convertIntegral<unsigned int>(parcelable.stepValue));
    mGain.min_ramp_ms = VALUE_OR_RETURN_STATUS(convertIntegral<unsigned int>(parcelable.minRampMs));
    mGain.max_ramp_ms = VALUE_OR_RETURN_STATUS(convertIntegral<unsigned int>(parcelable.maxRampMs));
    return OK;
}

bool AudioGains::equals(const AudioGains &other) const
{
    return std::equal(begin(), end(), other.begin(), other.end(),
                      [](const sp<AudioGain>& left, const sp<AudioGain>& right) {
                          return left->equals(right);
                      });
}

status_t AudioGains::writeToParcel(android::Parcel *parcel) const {
    status_t status = NO_ERROR;
    if ((status = parcel->writeVectorSize(*this)) != NO_ERROR) return status;
    for (const auto &audioGain : *this) {
        if ((status = parcel->writeParcelable(*audioGain)) != NO_ERROR) {
            break;
        }
    }
    return status;
}

status_t AudioGains::readFromParcel(const android::Parcel *parcel) {
    status_t status = NO_ERROR;
    this->clear();
    if ((status = parcel->resizeOutVector(this)) != NO_ERROR) return status;
    for (size_t i = 0; i < this->size(); i++) {
        this->at(i) = new AudioGain(0, false);
        if ((status = parcel->readParcelable(this->at(i).get())) != NO_ERROR) {
            this->clear();
            break;
        }
    }
    return status;
}

ConversionResult<sp<AudioGain>>
aidl2legacy_AudioGain(const media::AudioGain& aidl) {
    sp<AudioGain> legacy = new AudioGain(0, false);
    status_t status = legacy->readFromParcelable(aidl);
    if (status != OK) {
        return base::unexpected(status);
    }
    return legacy;
}

ConversionResult<media::AudioGain>
legacy2aidl_AudioGain(const sp<AudioGain>& legacy) {
    media::AudioGain aidl;
    status_t status = legacy->writeToParcelable(&aidl);
    if (status != OK) {
        return base::unexpected(status);
    }
    return aidl;
}

ConversionResult<AudioGains>
aidl2legacy_AudioGains(const std::vector<media::AudioGain>& aidl) {
    return convertContainer<AudioGains>(aidl, aidl2legacy_AudioGain);
}

ConversionResult<std::vector<media::AudioGain>>
legacy2aidl_AudioGains(const AudioGains& legacy) {
    return convertContainer<std::vector<media::AudioGain>>(legacy, legacy2aidl_AudioGain);
}

} // namespace android
