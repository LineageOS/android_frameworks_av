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

#define LOG_TAG "APM::IOProfile"
//#define LOG_NDEBUG 0

#include <system/audio.h>
#include "IOProfile.h"
#include "HwModule.h"
#include "TypeConverter.h"

namespace android {

IOProfile::IOProfile(const std::string &name, audio_port_role_t role)
        : AudioPort(name, AUDIO_PORT_TYPE_MIX, role),
          curOpenCount(0),
          curActiveCount(0) {
    if (role == AUDIO_PORT_ROLE_SOURCE) {
        mMixerBehaviors.insert(AUDIO_MIXER_BEHAVIOR_DEFAULT);
    }
}

bool IOProfile::isCompatibleProfile(const DeviceVector &devices,
                                    uint32_t samplingRate,
                                    uint32_t *updatedSamplingRate,
                                    audio_format_t format,
                                    audio_format_t *updatedFormat,
                                    audio_channel_mask_t channelMask,
                                    audio_channel_mask_t *updatedChannelMask,
                                    // FIXME type punning here
                                    uint32_t flags,
                                    bool exactMatchRequiredForInputFlags) const
{
    const bool isPlaybackThread =
            getType() == AUDIO_PORT_TYPE_MIX && getRole() == AUDIO_PORT_ROLE_SOURCE;
    const bool isRecordThread =
            getType() == AUDIO_PORT_TYPE_MIX && getRole() == AUDIO_PORT_ROLE_SINK;
    ALOG_ASSERT(isPlaybackThread != isRecordThread);
    if (!areAllDevicesSupported(devices) ||
            !isCompatibleProfileForFlags(flags, exactMatchRequiredForInputFlags)) {
        return false;
    }

    if (!audio_is_valid_format(format) ||
            (isPlaybackThread && (samplingRate == 0 || !audio_is_output_channel(channelMask))) ||
            (isRecordThread && (!audio_is_input_channel(channelMask)))) {
         return false;
    }

    audio_format_t myUpdatedFormat = format;
    audio_channel_mask_t myUpdatedChannelMask = channelMask;
    uint32_t myUpdatedSamplingRate = samplingRate;
    const struct audio_port_config config = {
        .config_mask = AUDIO_PORT_CONFIG_ALL & ~AUDIO_PORT_CONFIG_GAIN,
        .sample_rate = samplingRate,
        .channel_mask = channelMask,
        .format = format,
    };
    if (isRecordThread)
    {
        if ((flags & AUDIO_INPUT_FLAG_MMAP_NOIRQ) != 0) {
            if (checkExactAudioProfile(&config) != NO_ERROR) {
                return false;
            }
        } else if (checkCompatibleAudioProfile(
                myUpdatedSamplingRate, myUpdatedChannelMask, myUpdatedFormat) != NO_ERROR) {
            return false;
        }
    } else {
        if (checkExactAudioProfile(&config) != NO_ERROR) {
            return false;
        }
    }

    if (updatedSamplingRate != NULL) {
        *updatedSamplingRate = myUpdatedSamplingRate;
    }
    if (updatedFormat != NULL) {
        *updatedFormat = myUpdatedFormat;
    }
    if (updatedChannelMask != NULL) {
        *updatedChannelMask = myUpdatedChannelMask;
    }
    return true;
}

bool IOProfile::areAllDevicesSupported(const DeviceVector &devices) const {
    if (devices.empty()) {
        return true;
    }
    return mSupportedDevices.containsAllDevices(devices);
}

bool IOProfile::isCompatibleProfileForFlags(uint32_t flags,
                                            bool exactMatchRequiredForInputFlags) const {
    const bool isPlaybackThread =
            getType() == AUDIO_PORT_TYPE_MIX && getRole() == AUDIO_PORT_ROLE_SOURCE;
    const bool isRecordThread =
            getType() == AUDIO_PORT_TYPE_MIX && getRole() == AUDIO_PORT_ROLE_SINK;
    ALOG_ASSERT(isPlaybackThread != isRecordThread);

    const uint32_t mustMatchOutputFlags =
            AUDIO_OUTPUT_FLAG_DIRECT|AUDIO_OUTPUT_FLAG_HW_AV_SYNC|AUDIO_OUTPUT_FLAG_MMAP_NOIRQ;
    if (isPlaybackThread &&
        !audio_output_flags_is_subset((audio_output_flags_t)getFlags(),
                                      (audio_output_flags_t)flags,
                                      mustMatchOutputFlags)) {
        return false;
    }
    // The only input flag that is allowed to be different is the fast flag.
    // An existing fast stream is compatible with a normal track request.
    // An existing normal stream is compatible with a fast track request,
    // but the fast request will be denied by AudioFlinger and converted to normal track.
    if (isRecordThread && ((getFlags() ^ flags) &
            ~(exactMatchRequiredForInputFlags ? AUDIO_INPUT_FLAG_NONE : AUDIO_INPUT_FLAG_FAST))) {
        return false;
    }

    return true;
}

bool IOProfile::containsSingleDeviceSupportingEncodedFormats(
        const sp<DeviceDescriptor>& device) const {
    if (device == nullptr) {
        return false;
    }
    DeviceVector deviceList = mSupportedDevices.getDevicesFromType(device->type());
    return std::count_if(deviceList.begin(), deviceList.end(),
            [&device](sp<DeviceDescriptor> deviceDesc) {
                return device == deviceDesc && deviceDesc->hasCurrentEncodedFormat(); }) == 1;
}

void IOProfile::toSupportedMixerAttributes(
        std::vector<audio_mixer_attributes_t> *mixerAttributes) const {
    if (!hasDynamicAudioProfile()) {
        // The mixer attributes is only supported when there is a dynamic profile.
        return;
    }
    for (const auto& profile : mProfiles) {
        if (!profile->isValid()) {
            continue;
        }
        for (const auto sampleRate : profile->getSampleRates()) {
            for (const auto channelMask : profile->getChannels()) {
                const audio_config_base_t config = {
                        .format = profile->getFormat(),
                        .sample_rate = sampleRate,
                        .channel_mask = channelMask
                };
                for (const auto mixerBehavior : mMixerBehaviors) {
                    mixerAttributes->push_back({
                        .config = config,
                        .mixer_behavior = mixerBehavior
                    });
                }
            }
        }
    }
}

void IOProfile::refreshMixerBehaviors() {
    if (getRole() == AUDIO_PORT_ROLE_SOURCE) {
        mMixerBehaviors.clear();
        mMixerBehaviors.insert(AUDIO_MIXER_BEHAVIOR_DEFAULT);
        if (mFlags.output & AUDIO_OUTPUT_FLAG_BIT_PERFECT) {
            mMixerBehaviors.insert(AUDIO_MIXER_BEHAVIOR_BIT_PERFECT);
        }
    }
}

status_t IOProfile::readFromParcelable(const media::AudioPortFw &parcelable) {
    status_t status = AudioPort::readFromParcelable(parcelable);
    if (status == OK) {
        refreshMixerBehaviors();
    }
    return status;
}

void IOProfile::dump(String8 *dst, int spaces) const
{
    String8 extraInfo;
    extraInfo.appendFormat("0x%04x", getFlags());
    std::string flagsLiteral =
            getRole() == AUDIO_PORT_ROLE_SINK ?
            toString(static_cast<audio_input_flags_t>(getFlags())) :
            getRole() == AUDIO_PORT_ROLE_SOURCE ?
            toString(static_cast<audio_output_flags_t>(getFlags())) : "";
    if (!flagsLiteral.empty()) {
        extraInfo.appendFormat(" (%s)", flagsLiteral.c_str());
    }

    std::string portStr;
    AudioPort::dump(&portStr, spaces, extraInfo.c_str());
    dst->append(portStr.c_str());

    mSupportedDevices.dump(dst, String8("- Supported"), spaces - 2, false);
    dst->appendFormat("%*s- maxOpenCount: %u; curOpenCount: %u\n",
            spaces - 2, "", maxOpenCount, curOpenCount);
    dst->appendFormat("%*s- maxActiveCount: %u; curActiveCount: %u\n",
            spaces - 2, "", maxActiveCount, curActiveCount);
    dst->appendFormat("%*s- recommendedMuteDurationMs: %u ms\n",
            spaces - 2, "", recommendedMuteDurationMs);
    if (hasDynamicAudioProfile() && !mMixerBehaviors.empty()) {
        dst->appendFormat("%*s- mixerBehaviors: %s\n",
                spaces - 2, "", dumpMixerBehaviors(mMixerBehaviors).c_str());
    }
}

void IOProfile::log()
{
    // @TODO: forward log to AudioPort
}

} // namespace android
