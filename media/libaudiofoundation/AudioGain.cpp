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

status_t AudioGain::writeToParcel(android::Parcel *parcel) const
{
    status_t status = NO_ERROR;
    if ((status = parcel->writeInt32(mIndex)) != NO_ERROR) return status;
    if ((status = parcel->writeBool(mUseInChannelMask)) != NO_ERROR) return status;
    if ((status = parcel->writeBool(mUseForVolume)) != NO_ERROR) return status;
    if ((status = parcel->writeUint32(mGain.mode)) != NO_ERROR) return status;
    if ((status = parcel->writeUint32(mGain.channel_mask)) != NO_ERROR) return status;
    if ((status = parcel->writeInt32(mGain.min_value)) != NO_ERROR) return status;
    if ((status = parcel->writeInt32(mGain.max_value)) != NO_ERROR) return status;
    if ((status = parcel->writeInt32(mGain.default_value)) != NO_ERROR) return status;
    if ((status = parcel->writeUint32(mGain.step_value)) != NO_ERROR) return status;
    if ((status = parcel->writeUint32(mGain.min_ramp_ms)) != NO_ERROR) return status;
    status = parcel->writeUint32(mGain.max_ramp_ms);
    return status;
}

status_t AudioGain::readFromParcel(const android::Parcel *parcel)
{
    status_t status = NO_ERROR;
    if ((status = parcel->readInt32(&mIndex)) != NO_ERROR) return status;
    if ((status = parcel->readBool(&mUseInChannelMask)) != NO_ERROR) return status;
    if ((status = parcel->readBool(&mUseForVolume)) != NO_ERROR) return status;
    if ((status = parcel->readUint32(&mGain.mode)) != NO_ERROR) return status;
    if ((status = parcel->readUint32(&mGain.channel_mask)) != NO_ERROR) return status;
    if ((status = parcel->readInt32(&mGain.min_value)) != NO_ERROR) return status;
    if ((status = parcel->readInt32(&mGain.max_value)) != NO_ERROR) return status;
    if ((status = parcel->readInt32(&mGain.default_value)) != NO_ERROR) return status;
    if ((status = parcel->readUint32(&mGain.step_value)) != NO_ERROR) return status;
    if ((status = parcel->readUint32(&mGain.min_ramp_ms)) != NO_ERROR) return status;
    status = parcel->readUint32(&mGain.max_ramp_ms);
    return status;
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

} // namespace android
