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
#define LOG_TAG "AudioPort"

#include <algorithm>
#include <utility>

#include <android/media/ExtraAudioDescriptor.h>
#include <android-base/stringprintf.h>
#include <media/AudioPort.h>
#include <utils/Log.h>

namespace android {

void AudioPort::importAudioPort(const sp<AudioPort>& port, bool force __unused)
{
    for (const auto& profileToImport : port->mProfiles) {
        // Import only valid port, i.e. valid format, non empty rates and channels masks
        if (!profileToImport->isValid()) {
            continue;
        }
        if (std::find_if(mProfiles.begin(), mProfiles.end(),
                [profileToImport](const auto &profile) {
                        return *profile == *profileToImport; }) == mProfiles.end()) {
            addAudioProfile(profileToImport);
        }
    }
}

void AudioPort::importAudioPort(const audio_port_v7 &port) {
    for (size_t i = 0; i < port.num_audio_profiles; ++i) {
        sp<AudioProfile> profile = new AudioProfile(port.audio_profiles[i].format,
                ChannelMaskSet(port.audio_profiles[i].channel_masks,
                        port.audio_profiles[i].channel_masks +
                        port.audio_profiles->num_channel_masks),
                SampleRateSet(port.audio_profiles[i].sample_rates,
                        port.audio_profiles[i].sample_rates +
                        port.audio_profiles[i].num_sample_rates),
                port.audio_profiles[i].encapsulation_type);
        if (!mProfiles.contains(profile)) {
            addAudioProfile(profile);
        }
    }

    for (size_t i = 0; i < port.num_extra_audio_descriptors; ++i) {
        auto convertedResult = legacy2aidl_audio_extra_audio_descriptor_ExtraAudioDescriptor(
                port.extra_audio_descriptors[i]);
        if (!convertedResult.ok()) {
            ALOGE("%s, failed to convert extra audio descriptor", __func__);
            continue;
        }
        if (std::find(mExtraAudioDescriptors.begin(),
                      mExtraAudioDescriptors.end(),
                      convertedResult.value()) == mExtraAudioDescriptors.end()) {
            mExtraAudioDescriptors.push_back(std::move(convertedResult.value()));
        }
    }
}

void AudioPort::toAudioPort(struct audio_port *port) const {
    // TODO: update this function once audio_port structure reflects the new profile definition.
    // For compatibility reason: flatening the AudioProfile into audio_port structure.
    FormatSet flatenedFormats;
    SampleRateSet flatenedRates;
    ChannelMaskSet flatenedChannels;
    for (const auto& profile : mProfiles) {
        if (profile->isValid()) {
            audio_format_t formatToExport = profile->getFormat();
            const SampleRateSet &ratesToExport = profile->getSampleRates();
            const ChannelMaskSet &channelsToExport = profile->getChannels();

            flatenedFormats.insert(formatToExport);
            flatenedRates.insert(ratesToExport.begin(), ratesToExport.end());
            flatenedChannels.insert(channelsToExport.begin(), channelsToExport.end());

            if (flatenedRates.size() > AUDIO_PORT_MAX_SAMPLING_RATES ||
                    flatenedChannels.size() > AUDIO_PORT_MAX_CHANNEL_MASKS ||
                    flatenedFormats.size() > AUDIO_PORT_MAX_FORMATS) {
                ALOGE("%s: bailing out: cannot export profiles to port config", __func__);
                return;
            }
        }
    }
    toAudioPortBase(port);
    port->num_sample_rates = flatenedRates.size();
    port->num_channel_masks = flatenedChannels.size();
    port->num_formats = flatenedFormats.size();
    std::copy(flatenedRates.begin(), flatenedRates.end(), port->sample_rates);
    std::copy(flatenedChannels.begin(), flatenedChannels.end(), port->channel_masks);
    std::copy(flatenedFormats.begin(), flatenedFormats.end(), port->formats);
}

void AudioPort::toAudioPort(struct audio_port_v7 *port) const {
    toAudioPortBase(port);
    port->num_audio_profiles = 0;
    for (const auto& profile : mProfiles) {
        if (profile->isValid()) {
            const SampleRateSet &sampleRates = profile->getSampleRates();
            const ChannelMaskSet &channelMasks = profile->getChannels();

            if (sampleRates.size() > AUDIO_PORT_MAX_SAMPLING_RATES ||
                    channelMasks.size() > AUDIO_PORT_MAX_CHANNEL_MASKS ||
                    port->num_audio_profiles >= AUDIO_PORT_MAX_AUDIO_PROFILES) {
                ALOGE("%s: bailing out: cannot export profiles to port config", __func__);
                break;
            }

            auto& dstProfile = port->audio_profiles[port->num_audio_profiles++];
            dstProfile.format = profile->getFormat();
            dstProfile.num_sample_rates = sampleRates.size();
            std::copy(sampleRates.begin(), sampleRates.end(),
                    std::begin(dstProfile.sample_rates));
            dstProfile.num_channel_masks = channelMasks.size();
            std::copy(channelMasks.begin(), channelMasks.end(),
                    std::begin(dstProfile.channel_masks));
            dstProfile.encapsulation_type = profile->getEncapsulationType();
        }
    }

    port->num_extra_audio_descriptors = 0;
    for (const auto& desc : mExtraAudioDescriptors) {
        if (port->num_extra_audio_descriptors >= AUDIO_PORT_MAX_EXTRA_AUDIO_DESCRIPTORS) {
            ALOGE("%s: bailing out: cannot export extra audio descriptor to port config", __func__);
            return;
        }

        auto convertedResult = aidl2legacy_ExtraAudioDescriptor_audio_extra_audio_descriptor(desc);
        if (!convertedResult.ok()) {
            ALOGE("%s: failed to convert extra audio descriptor", __func__);
            continue;
        }
        port->extra_audio_descriptors[port->num_extra_audio_descriptors++] =
                std::move(convertedResult.value());
    }
}

void AudioPort::dump(std::string *dst, int spaces, bool verbose) const {
    if (!mName.empty()) {
        dst->append(base::StringPrintf("%*s- name: %s\n", spaces, "", mName.c_str()));
    }
    if (verbose) {
        std::string profilesStr;
        mProfiles.dump(&profilesStr, spaces);
        dst->append(profilesStr);
        if (!mExtraAudioDescriptors.empty()) {
            dst->append(base::StringPrintf("%*s- extra audio descriptors: \n", spaces, ""));
            const int eadSpaces = spaces + 4;
            const int descSpaces = eadSpaces + 4;
            for (size_t i = 0; i < mExtraAudioDescriptors.size(); i++) {
                dst->append(
                        base::StringPrintf("%*s extra audio descriptor %zu:\n", eadSpaces, "", i));
                dst->append(base::StringPrintf(
                    "%*s- standard: %u\n", descSpaces, "", mExtraAudioDescriptors[i].standard));
                dst->append(base::StringPrintf("%*s- descriptor:", descSpaces, ""));
                for (auto v : mExtraAudioDescriptors[i].audioDescriptor) {
                    dst->append(base::StringPrintf(" %02x", v));
                }
                dst->append("\n");
            }
        }

        if (mGains.size() != 0) {
            dst->append(base::StringPrintf("%*s- gains:\n", spaces, ""));
            for (size_t i = 0; i < mGains.size(); i++) {
                std::string gainStr;
                mGains[i]->dump(&gainStr, spaces + 2, i);
                dst->append(gainStr);
            }
        }
    }
}

void AudioPort::log(const char* indent) const
{
    ALOGI("%s Port[nm:%s, type:%d, role:%d]", indent, mName.c_str(), mType, mRole);
}

bool AudioPort::equals(const sp<AudioPort> &other) const
{
    return other != nullptr &&
           mGains.equals(other->getGains()) &&
           mName.compare(other->getName()) == 0 &&
           mType == other->getType() &&
           mRole == other->getRole() &&
           mProfiles.equals(other->getAudioProfiles()) &&
           mExtraAudioDescriptors == other->getExtraAudioDescriptors();
}

status_t AudioPort::writeToParcel(Parcel *parcel) const
{
    media::AudioPort parcelable;
    return writeToParcelable(&parcelable)
        ?: parcelable.writeToParcel(parcel);
}

status_t AudioPort::writeToParcelable(media::AudioPort* parcelable) const {
    parcelable->name = mName;
    parcelable->type = VALUE_OR_RETURN_STATUS(legacy2aidl_audio_port_type_t_AudioPortType(mType));
    parcelable->role = VALUE_OR_RETURN_STATUS(legacy2aidl_audio_port_role_t_AudioPortRole(mRole));
    parcelable->profiles = VALUE_OR_RETURN_STATUS(legacy2aidl_AudioProfileVector(mProfiles));
    parcelable->extraAudioDescriptors = mExtraAudioDescriptors;
    parcelable->gains = VALUE_OR_RETURN_STATUS(legacy2aidl_AudioGains(mGains));
    return OK;
}

status_t AudioPort::readFromParcel(const Parcel *parcel) {
    media::AudioPort parcelable;
    return parcelable.readFromParcel(parcel)
        ?: readFromParcelable(parcelable);
}

status_t AudioPort::readFromParcelable(const media::AudioPort& parcelable) {
    mName = parcelable.name;
    mType = VALUE_OR_RETURN_STATUS(aidl2legacy_AudioPortType_audio_port_type_t(parcelable.type));
    mRole = VALUE_OR_RETURN_STATUS(aidl2legacy_AudioPortRole_audio_port_role_t(parcelable.role));
    mProfiles = VALUE_OR_RETURN_STATUS(aidl2legacy_AudioProfileVector(parcelable.profiles));
    mExtraAudioDescriptors = parcelable.extraAudioDescriptors;
    mGains = VALUE_OR_RETURN_STATUS(aidl2legacy_AudioGains(parcelable.gains));
    return OK;
}

// --- AudioPortConfig class implementation

status_t AudioPortConfig::applyAudioPortConfig(
        const struct audio_port_config *config,
        struct audio_port_config *backupConfig __unused)
{
    if (config->config_mask & AUDIO_PORT_CONFIG_SAMPLE_RATE) {
        mSamplingRate = config->sample_rate;
    }
    if (config->config_mask & AUDIO_PORT_CONFIG_CHANNEL_MASK) {
        mChannelMask = config->channel_mask;
    }
    if (config->config_mask & AUDIO_PORT_CONFIG_FORMAT) {
        mFormat = config->format;
    }
    if (config->config_mask & AUDIO_PORT_CONFIG_GAIN) {
        mGain = config->gain;
    }

    return NO_ERROR;
}

namespace {

template<typename T>
void updateField(
        const T& portConfigField, T audio_port_config::*port_config_field,
        struct audio_port_config *dstConfig, const struct audio_port_config *srcConfig,
        unsigned int configMask, T defaultValue)
{
    if (dstConfig->config_mask & configMask) {
        if ((srcConfig != nullptr) && (srcConfig->config_mask & configMask)) {
            dstConfig->*port_config_field = srcConfig->*port_config_field;
        } else {
            dstConfig->*port_config_field = portConfigField;
        }
    } else {
        dstConfig->*port_config_field = defaultValue;
    }
}

} // namespace

void AudioPortConfig::toAudioPortConfig(
        struct audio_port_config *dstConfig,
        const struct audio_port_config *srcConfig) const
{
    updateField(mSamplingRate, &audio_port_config::sample_rate,
            dstConfig, srcConfig, AUDIO_PORT_CONFIG_SAMPLE_RATE, 0u);
    updateField(mChannelMask, &audio_port_config::channel_mask,
            dstConfig, srcConfig, AUDIO_PORT_CONFIG_CHANNEL_MASK,
            (audio_channel_mask_t)AUDIO_CHANNEL_NONE);
    updateField(mFormat, &audio_port_config::format,
            dstConfig, srcConfig, AUDIO_PORT_CONFIG_FORMAT, AUDIO_FORMAT_INVALID);
    dstConfig->id = mId;

    sp<AudioPort> audioport = getAudioPort();
    if ((dstConfig->config_mask & AUDIO_PORT_CONFIG_GAIN) && audioport != NULL) {
        dstConfig->gain = mGain;
        if ((srcConfig != NULL) && (srcConfig->config_mask & AUDIO_PORT_CONFIG_GAIN)
                && audioport->checkGain(&srcConfig->gain, srcConfig->gain.index) == OK) {
            dstConfig->gain = srcConfig->gain;
        }
    } else {
        dstConfig->gain.index = -1;
    }
    if (dstConfig->gain.index != -1) {
        dstConfig->config_mask |= AUDIO_PORT_CONFIG_GAIN;
    } else {
        dstConfig->config_mask &= ~AUDIO_PORT_CONFIG_GAIN;
    }
}

bool AudioPortConfig::hasGainController(bool canUseForVolume) const
{
    sp<AudioPort> audioport = getAudioPort();
    if (!audioport) {
        return false;
    }
    return canUseForVolume ? audioport->getGains().canUseForVolume()
                           : audioport->getGains().size() > 0;
}

bool AudioPortConfig::equals(const sp<AudioPortConfig> &other) const
{
    return other != nullptr &&
           mSamplingRate == other->getSamplingRate() &&
           mFormat == other->getFormat() &&
           mChannelMask == other->getChannelMask() &&
           // Compare audio gain config
           mGain.index == other->mGain.index &&
           mGain.mode == other->mGain.mode &&
           mGain.channel_mask == other->mGain.channel_mask &&
           std::equal(std::begin(mGain.values), std::end(mGain.values),
                      std::begin(other->mGain.values)) &&
           mGain.ramp_duration_ms == other->mGain.ramp_duration_ms;
}

status_t AudioPortConfig::writeToParcel(Parcel *parcel) const {
    media::AudioPortConfig parcelable;
    return writeToParcelable(&parcelable)
        ?: parcelable.writeToParcel(parcel);
}

status_t AudioPortConfig::writeToParcelable(media::AudioPortConfig* parcelable) const {
    parcelable->sampleRate = VALUE_OR_RETURN_STATUS(convertIntegral<int32_t>(mSamplingRate));
    parcelable->format = VALUE_OR_RETURN_STATUS(legacy2aidl_audio_format_t_AudioFormat(mFormat));
    parcelable->channelMask = VALUE_OR_RETURN_STATUS(
            legacy2aidl_audio_channel_mask_t_int32_t(mChannelMask));
    parcelable->id = VALUE_OR_RETURN_STATUS(legacy2aidl_audio_port_handle_t_int32_t(mId));
    parcelable->gain.index = VALUE_OR_RETURN_STATUS(convertIntegral<int32_t>(mGain.index));
    parcelable->gain.mode = VALUE_OR_RETURN_STATUS(
            legacy2aidl_audio_gain_mode_t_int32_t_mask(mGain.mode));
    parcelable->gain.channelMask = VALUE_OR_RETURN_STATUS(
            legacy2aidl_audio_channel_mask_t_int32_t(mGain.channel_mask));
    parcelable->gain.rampDurationMs = VALUE_OR_RETURN_STATUS(
            convertIntegral<int32_t>(mGain.ramp_duration_ms));
    parcelable->gain.values = VALUE_OR_RETURN_STATUS(convertContainer<std::vector<int32_t>>(
            mGain.values, convertIntegral<int32_t, int>));
    return OK;
}

status_t AudioPortConfig::readFromParcel(const Parcel *parcel) {
    media::AudioPortConfig parcelable;
    return parcelable.readFromParcel(parcel)
        ?: readFromParcelable(parcelable);
}

status_t AudioPortConfig::readFromParcelable(const media::AudioPortConfig& parcelable) {
    mSamplingRate = VALUE_OR_RETURN_STATUS(convertIntegral<unsigned int>(parcelable.sampleRate));
    mFormat = VALUE_OR_RETURN_STATUS(aidl2legacy_AudioFormat_audio_format_t(parcelable.format));
    mChannelMask = VALUE_OR_RETURN_STATUS(
            aidl2legacy_int32_t_audio_channel_mask_t(parcelable.channelMask));
    mId = VALUE_OR_RETURN_STATUS(aidl2legacy_int32_t_audio_port_handle_t(parcelable.id));
    mGain.index = VALUE_OR_RETURN_STATUS(convertIntegral<int>(parcelable.gain.index));
    mGain.mode = VALUE_OR_RETURN_STATUS(
            aidl2legacy_int32_t_audio_gain_mode_t_mask(parcelable.gain.mode));
    mGain.channel_mask = VALUE_OR_RETURN_STATUS(
            aidl2legacy_int32_t_audio_channel_mask_t(parcelable.gain.channelMask));
    mGain.ramp_duration_ms = VALUE_OR_RETURN_STATUS(
            convertIntegral<unsigned int>(parcelable.gain.rampDurationMs));
    if (parcelable.gain.values.size() > std::size(mGain.values)) {
        return BAD_VALUE;
    }
    for (size_t i = 0; i < parcelable.gain.values.size(); ++i) {
        mGain.values[i] = VALUE_OR_RETURN_STATUS(convertIntegral<int>(parcelable.gain.values[i]));
    }
    return OK;
}

} // namespace android
