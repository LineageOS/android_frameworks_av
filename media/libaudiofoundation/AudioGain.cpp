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

#include <math.h>

#include <algorithm>

#include <android-base/stringprintf.h>
#include <media/AudioGain.h>
#include <utils/Log.h>

namespace android {

AudioGain::AudioGain(int index, bool isInput)
        : mIndex(index), mIsInput(isInput) {}

void AudioGain::getDefaultConfig(struct audio_gain_config *config)
{
    config->index = mIndex;
    config->mode = mGain.mode;
    config->channel_mask = mGain.channel_mask;
    if ((mGain.mode & AUDIO_GAIN_MODE_JOINT) == AUDIO_GAIN_MODE_JOINT) {
        config->values[0] = mGain.default_value;
    } else {
        const uint32_t numValues = mIsInput ?
                audio_channel_count_from_in_mask(mGain.channel_mask) :
                audio_channel_count_from_out_mask(mGain.channel_mask);
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
        const uint32_t numValues = mIsInput ?
                audio_channel_count_from_in_mask(config->channel_mask) :
                audio_channel_count_from_out_mask(config->channel_mask);
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
           mIsInput == other->mIsInput &&
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

ConversionResult<AudioGain::Aidl> AudioGain::toParcelable() const {
    media::audio::common::AudioGain aidl = VALUE_OR_RETURN(
            legacy2aidl_audio_gain_AudioGain(mGain, mIsInput));
    aidl.useForVolume = mUseForVolume;
    media::AudioGainSys aidlSys;
    aidlSys.index = VALUE_OR_RETURN(convertIntegral<int32_t>(mIndex));
    aidlSys.isInput = mIsInput;
    return std::make_pair(aidl, aidlSys);
}

ConversionResult<sp<AudioGain>> AudioGain::fromParcelable(const AudioGain::Aidl& aidl) {
    const media::audio::common::AudioGain& hal = aidl.first;
    const media::AudioGainSys& sys = aidl.second;
    auto index = VALUE_OR_RETURN(convertIntegral<int>(sys.index));
    sp<AudioGain> legacy = sp<AudioGain>::make(index, sys.isInput);
    legacy->mGain = VALUE_OR_RETURN(aidl2legacy_AudioGain_audio_gain(hal, sys.isInput));
    legacy->mUseForVolume = hal.useForVolume;
    return legacy;
}

bool AudioGains::equals(const AudioGains &other) const
{
    return std::equal(begin(), end(), other.begin(), other.end(),
                      [](const sp<AudioGain>& left, const sp<AudioGain>& right) {
                          return left->equals(right);
                      });
}

ConversionResult<sp<AudioGain>>
aidl2legacy_AudioGain(const AudioGain::Aidl& aidl) {
    return AudioGain::fromParcelable(aidl);
}

ConversionResult<AudioGain::Aidl>
legacy2aidl_AudioGain(const sp<AudioGain>& legacy) {
    return legacy->toParcelable();
}

ConversionResult<AudioGains>
aidl2legacy_AudioGains(const AudioGains::Aidl& aidl) {
    return convertContainers<AudioGains>(aidl.first, aidl.second,
            [](const media::audio::common::AudioGain& g,
               const media::AudioGainSys& gs) {
                return aidl2legacy_AudioGain(std::make_pair(g, gs));
            });
}

ConversionResult<AudioGains::Aidl>
legacy2aidl_AudioGains(const AudioGains& legacy) {
    return convertContainerSplit<
            std::vector<media::audio::common::AudioGain>,
            std::vector<media::AudioGainSys>>(legacy, legacy2aidl_AudioGain);
}

} // namespace android
