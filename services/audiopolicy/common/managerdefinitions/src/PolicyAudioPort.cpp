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

#define LOG_TAG "APM::PolicyAudioPort"
//#define LOG_NDEBUG 0
#include "TypeConverter.h"
#include "PolicyAudioPort.h"
#include "HwModule.h"
#include <policy.h>

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

namespace android {

// --- PolicyAudioPort class implementation
void PolicyAudioPort::attach(const sp<HwModule>& module)
{
    ALOGV("%s: attaching module %s to port %s",
            __FUNCTION__, getModuleName(), asAudioPort()->getName().c_str());
    mModule = module;
}

void PolicyAudioPort::detach()
{
    mModule = nullptr;
}

// Note that is a different namespace than AudioFlinger unique IDs
audio_port_handle_t PolicyAudioPort::getNextUniqueId()
{
    return getNextHandle();
}

audio_module_handle_t PolicyAudioPort::getModuleHandle() const
{
    return mModule != 0 ? mModule->getHandle() : AUDIO_MODULE_HANDLE_NONE;
}

uint32_t PolicyAudioPort::getModuleVersionMajor() const
{
    return mModule != 0 ? mModule->getHalVersionMajor() : 0;
}

const char *PolicyAudioPort::getModuleName() const
{
    return mModule != 0 ? mModule->getName() : "invalid module";
}

status_t PolicyAudioPort::checkExactAudioProfile(const struct audio_port_config *config) const
{
    status_t status = NO_ERROR;
    auto config_mask = config->config_mask;
    if (config_mask & AUDIO_PORT_CONFIG_GAIN) {
        config_mask &= ~AUDIO_PORT_CONFIG_GAIN;
        status = asAudioPort()->checkGain(&config->gain, config->gain.index);
        if (status != NO_ERROR) {
            return status;
        }
    }
    if (config_mask != 0) {
        // TODO should we check sample_rate / channel_mask / format separately?
        status = checkExactProfile(asAudioPort()->getAudioProfiles(), config->sample_rate,
                config->channel_mask, config->format);
    }
    return status;
}

void PolicyAudioPort::pickSamplingRate(uint32_t &pickedRate,
                                       const SampleRateSet &samplingRates) const
{
    pickedRate = 0;
    // For direct outputs, pick minimum sampling rate: this helps ensuring that the
    // channel count / sampling rate combination chosen will be supported by the connected
    // sink
    if (isDirectOutput()) {
        uint32_t samplingRate = UINT_MAX;
        for (const auto rate : samplingRates) {
            if ((rate < samplingRate) && (rate > 0)) {
                samplingRate = rate;
            }
        }
        pickedRate = (samplingRate == UINT_MAX) ? 0 : samplingRate;
    } else {
        uint32_t maxRate = SAMPLE_RATE_HZ_MAX;

        // For mixed output and inputs, use max mixer sampling rates. Do not
        // limit sampling rate otherwise
        // For inputs, also see checkCompatibleSamplingRate().
        if (asAudioPort()->getType() == AUDIO_PORT_TYPE_MIX) {
            maxRate = UINT_MAX;
        }
        // TODO: should mSamplingRates[] be ordered in terms of our preference
        // and we return the first (and hence most preferred) match?  This is of concern if
        // we want to choose 96kHz over 192kHz for USB driver stability or resource constraints.
        for (const auto rate : samplingRates) {
            if ((rate > pickedRate) && (rate <= maxRate)) {
                pickedRate = rate;
            }
        }
    }
}

void PolicyAudioPort::pickChannelMask(audio_channel_mask_t &pickedChannelMask,
                                      const ChannelMaskSet &channelMasks) const
{
    pickedChannelMask = AUDIO_CHANNEL_NONE;
    // For direct outputs, pick minimum channel count: this helps ensuring that the
    // channel count / sampling rate combination chosen will be supported by the connected
    // sink
    if (isDirectOutput()) {
        uint32_t channelCount = UINT_MAX;
        for (const auto channelMask : channelMasks) {
            uint32_t cnlCount;
            if (asAudioPort()->useInputChannelMask()) {
                cnlCount = audio_channel_count_from_in_mask(channelMask);
            } else {
                cnlCount = audio_channel_count_from_out_mask(channelMask);
            }
            if ((cnlCount < channelCount) && (cnlCount > 0)) {
                pickedChannelMask = channelMask;
                channelCount = cnlCount;
            }
        }
    } else {
        uint32_t channelCount = 0;
        uint32_t maxCount = MAX_MIXER_CHANNEL_COUNT;

        // For mixed output and inputs, use max mixer channel count. Do not
        // limit channel count otherwise
        if (asAudioPort()->getType() != AUDIO_PORT_TYPE_MIX) {
            maxCount = UINT_MAX;
        }
        for (const auto channelMask : channelMasks) {
            uint32_t cnlCount;
            if (asAudioPort()->useInputChannelMask()) {
                cnlCount = audio_channel_count_from_in_mask(channelMask);
            } else {
                cnlCount = audio_channel_count_from_out_mask(channelMask);
            }
            if ((cnlCount > channelCount) && (cnlCount <= maxCount)) {
                pickedChannelMask = channelMask;
                channelCount = cnlCount;
            }
        }
    }
}

/* format in order of increasing preference */
const audio_format_t PolicyAudioPort::sPcmFormatCompareTable[] = {
        AUDIO_FORMAT_DEFAULT,
        AUDIO_FORMAT_PCM_16_BIT,
        AUDIO_FORMAT_PCM_8_24_BIT,
        AUDIO_FORMAT_PCM_24_BIT_PACKED,
        AUDIO_FORMAT_PCM_32_BIT,
        AUDIO_FORMAT_PCM_FLOAT,
};

int PolicyAudioPort::compareFormats(audio_format_t format1, audio_format_t format2)
{
    // NOTE: AUDIO_FORMAT_INVALID is also considered not PCM and will be compared equal to any
    // compressed format and better than any PCM format. This is by design of pickFormat()
    if (!audio_is_linear_pcm(format1)) {
        if (!audio_is_linear_pcm(format2)) {
            return 0;
        }
        return 1;
    }
    if (!audio_is_linear_pcm(format2)) {
        return -1;
    }

    int index1 = -1, index2 = -1;
    for (size_t i = 0;
            (i < ARRAY_SIZE(sPcmFormatCompareTable)) && ((index1 == -1) || (index2 == -1));
            i ++) {
        if (sPcmFormatCompareTable[i] == format1) {
            index1 = i;
        }
        if (sPcmFormatCompareTable[i] == format2) {
            index2 = i;
        }
    }
    // format1 not found => index1 < 0 => format2 > format1
    // format2 not found => index2 < 0 => format2 < format1
    return index1 - index2;
}

uint32_t PolicyAudioPort::formatDistance(audio_format_t format1, audio_format_t format2)
{
    if (format1 == format2) {
        return 0;
    }
    if (format1 == AUDIO_FORMAT_INVALID || format2 == AUDIO_FORMAT_INVALID) {
        return kFormatDistanceMax;
    }
    int diffBytes = (int)audio_bytes_per_sample(format1) -
            audio_bytes_per_sample(format2);

    return abs(diffBytes);
}

bool PolicyAudioPort::isBetterFormatMatch(audio_format_t newFormat,
                                          audio_format_t currentFormat,
                                          audio_format_t targetFormat)
{
    return formatDistance(newFormat, targetFormat) < formatDistance(currentFormat, targetFormat);
}

void PolicyAudioPort::pickAudioProfile(uint32_t &samplingRate,
                                       audio_channel_mask_t &channelMask,
                                       audio_format_t &format) const
{
    format = AUDIO_FORMAT_DEFAULT;
    samplingRate = 0;
    channelMask = AUDIO_CHANNEL_NONE;

    // special case for uninitialized dynamic profile
    if (!asAudioPort()->hasValidAudioProfile()) {
        return;
    }
    audio_format_t bestFormat = sPcmFormatCompareTable[ARRAY_SIZE(sPcmFormatCompareTable) - 1];
    // For mixed output and inputs, use best mixer output format.
    // Do not limit format otherwise
    if ((asAudioPort()->getType() != AUDIO_PORT_TYPE_MIX) || isDirectOutput()) {
        bestFormat = AUDIO_FORMAT_INVALID;
    }

    const AudioProfileVector& audioProfiles = asAudioPort()->getAudioProfiles();
    for (size_t i = 0; i < audioProfiles.size(); i ++) {
        if (!audioProfiles[i]->isValid()) {
            continue;
        }
        audio_format_t formatToCompare = audioProfiles[i]->getFormat();
        if ((compareFormats(formatToCompare, format) > 0) &&
                (compareFormats(formatToCompare, bestFormat) <= 0)) {
            uint32_t pickedSamplingRate = 0;
            audio_channel_mask_t pickedChannelMask = AUDIO_CHANNEL_NONE;
            pickChannelMask(pickedChannelMask, audioProfiles[i]->getChannels());
            pickSamplingRate(pickedSamplingRate, audioProfiles[i]->getSampleRates());

            if (formatToCompare != AUDIO_FORMAT_DEFAULT && pickedChannelMask != AUDIO_CHANNEL_NONE
                    && pickedSamplingRate != 0) {
                format = formatToCompare;
                channelMask = pickedChannelMask;
                samplingRate = pickedSamplingRate;
                // TODO: shall we return on the first one or still trying to pick a better Profile?
            }
        }
    }
    ALOGV("%s Port[nm:%s] profile rate=%d, format=%d, channels=%d", __FUNCTION__,
            asAudioPort()->getName().c_str(), samplingRate, channelMask, format);
}

// --- PolicyAudioPortConfig class implementation

status_t PolicyAudioPortConfig::validationBeforeApplyConfig(
        const struct audio_port_config *config) const
{
    sp<PolicyAudioPort> policyAudioPort = getPolicyAudioPort();
    return policyAudioPort ? policyAudioPort->checkExactAudioProfile(config) : NO_INIT;
}

void PolicyAudioPortConfig::toPolicyAudioPortConfig(struct audio_port_config *dstConfig,
                                                    const struct audio_port_config *srcConfig) const
{
    if (dstConfig->config_mask & AUDIO_PORT_CONFIG_FLAGS) {
        if ((srcConfig != nullptr) && (srcConfig->config_mask & AUDIO_PORT_CONFIG_FLAGS)) {
            dstConfig->flags = srcConfig->flags;
        } else {
            dstConfig->flags = mFlags;
        }
    } else {
        dstConfig->flags = { AUDIO_INPUT_FLAG_NONE };
    }
}



} // namespace android
