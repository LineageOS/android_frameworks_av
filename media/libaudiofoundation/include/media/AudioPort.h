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

#pragma once

#include <string>
#include <type_traits>

#include <android/media/AudioPortFw.h>
#include <android/media/AudioPortConfigFw.h>
#include <android/media/audio/common/ExtraAudioDescriptor.h>
#include <binder/Parcel.h>
#include <binder/Parcelable.h>
#include <media/AudioGain.h>
#include <media/AudioProfile.h>
#include <utils/Errors.h>
#include <utils/RefBase.h>
#include <system/audio.h>
#include <cutils/config_utils.h>

namespace android {

class AudioPort : public virtual RefBase
{
public:
    AudioPort(const std::string& name, audio_port_type_t type,  audio_port_role_t role) :
            mName(name), mType(type), mRole(role) {}

    virtual ~AudioPort() = default;

    void setName(const std::string &name) { mName = name; }
    const std::string &getName() const { return mName; }

    audio_port_type_t getType() const { return mType; }
    audio_port_role_t getRole() const { return mRole; }

    virtual void setFlags(uint32_t flags);
    uint32_t getFlags() const {
        return useInputChannelMask() ? static_cast<uint32_t>(mFlags.input)
                                     : static_cast<uint32_t>(mFlags.output);
    }

    void setGains(const AudioGains &gains) { mGains = gains; }
    const AudioGains &getGains() const { return mGains; }

    virtual void toAudioPort(struct audio_port *port) const;

    virtual void toAudioPort(struct audio_port_v7 *port) const;

    virtual void addAudioProfile(const sp<AudioProfile> &profile) {
        mProfiles.add(profile);
    }
    virtual void clearAudioProfiles() {
        mProfiles.clearProfiles();
    }

    bool hasValidAudioProfile() const { return mProfiles.hasValidProfile(); }

    bool hasDynamicAudioProfile() const { return mProfiles.hasDynamicProfile(); }

    void setAudioProfiles(const AudioProfileVector &profiles) { mProfiles = profiles; }
    AudioProfileVector &getAudioProfiles() { return mProfiles; }

    void setExtraAudioDescriptors(
            const std::vector<media::audio::common::ExtraAudioDescriptor>& extraAudioDescriptors) {
        mExtraAudioDescriptors = extraAudioDescriptors;
    }
    std::vector<media::audio::common::ExtraAudioDescriptor> &getExtraAudioDescriptors() {
        return mExtraAudioDescriptors;
    }

    virtual void importAudioPort(const sp<AudioPort>& port, bool force = false);

    virtual void importAudioPort(const audio_port_v7& port);

    status_t checkGain(const struct audio_gain_config *gainConfig, int index) const {
        if (index < 0 || (size_t)index >= mGains.size()) {
            return BAD_VALUE;
        }
        return mGains[index]->checkConfig(gainConfig);
    }

    bool useInputChannelMask() const
    {
        return ((mType == AUDIO_PORT_TYPE_DEVICE) && (mRole == AUDIO_PORT_ROLE_SOURCE)) ||
                ((mType == AUDIO_PORT_TYPE_MIX) && (mRole == AUDIO_PORT_ROLE_SINK));
    }

    bool isDirectOutput() const
    {
        return (mType == AUDIO_PORT_TYPE_MIX) && (mRole == AUDIO_PORT_ROLE_SOURCE) &&
                ((mFlags.output & AUDIO_OUTPUT_FLAG_DIRECT) != 0);
    }

    bool isMmap() const
    {
        return (mType == AUDIO_PORT_TYPE_MIX)
                && (((mRole == AUDIO_PORT_ROLE_SOURCE) &&
                        ((mFlags.output & AUDIO_OUTPUT_FLAG_MMAP_NOIRQ) != 0))
                    || ((mRole == AUDIO_PORT_ROLE_SINK) &&
                        ((mFlags.input & AUDIO_INPUT_FLAG_MMAP_NOIRQ) != 0)));
    }

    void dump(std::string *dst, int spaces,
              const char* extraInfo = nullptr, bool verbose = true) const;

    void log(const char* indent) const;

    bool equals(const sp<AudioPort>& other) const;

    status_t writeToParcelable(media::AudioPortFw* parcelable) const;
    status_t readFromParcelable(const media::AudioPortFw& parcelable);

    AudioGains mGains; // gain controllers
    // Maximum number of input or output streams that can be simultaneously
    // opened for this profile. By convention 0 means no limit. To respect
    // legacy behavior, initialized to 1 for output profiles and 0 for input
    // profiles
    // FIXME: IOProfile code used the same value for both cases.
    uint32_t maxOpenCount = 1;
    // Maximum number of input or output streams that can be simultaneously
    // active for this profile. By convention 0 means no limit. To respect
    // legacy behavior, initialized to 0 for output profiles and 1 for input
    // profiles
    // FIXME: IOProfile code used the same value for both cases.
    uint32_t maxActiveCount = 1;
    // Mute duration while changing device on this output profile.
    uint32_t recommendedMuteDurationMs = 0;

protected:
    std::string  mName;
    audio_port_type_t mType;
    audio_port_role_t mRole;
    AudioProfileVector mProfiles; // AudioProfiles supported by this port (format, Rates, Channels)

    // Audio capabilities that are defined by hardware descriptors when the format is unrecognized
    // by the platform, e.g. short audio descriptor in EDID for HDMI.
    std::vector<media::audio::common::ExtraAudioDescriptor> mExtraAudioDescriptors;
    union audio_io_flags mFlags = { .output = AUDIO_OUTPUT_FLAG_NONE };
private:
    template <typename T, std::enable_if_t<std::is_same<T, struct audio_port>::value
                                        || std::is_same<T, struct audio_port_v7>::value, int> = 0>
    void toAudioPortBase(T* port) const {
        port->role = mRole;
        port->type = mType;
        strlcpy(port->name, mName.c_str(), AUDIO_PORT_MAX_NAME_LEN);
        port->num_gains = std::min(mGains.size(), (size_t) AUDIO_PORT_MAX_GAINS);
        for (size_t i = 0; i < port->num_gains; i++) {
            port->gains[i] = mGains[i]->getGain();
        }
    }
};


class AudioPortConfig : public virtual RefBase
{
public:
    virtual ~AudioPortConfig() = default;

    virtual sp<AudioPort> getAudioPort() const = 0;

    virtual status_t applyAudioPortConfig(const struct audio_port_config *config,
                                          struct audio_port_config *backupConfig = NULL);

    virtual void toAudioPortConfig(struct audio_port_config *dstConfig,
                                   const struct audio_port_config *srcConfig = NULL) const;

    unsigned int getSamplingRate() const { return mSamplingRate; }
    audio_format_t getFormat() const { return mFormat; }
    audio_channel_mask_t getChannelMask() const { return mChannelMask; }
    audio_port_handle_t getId() const { return mId; }
    audio_io_flags getFlags() const { return mFlags; }

    bool hasGainController(bool canUseForVolume = false) const;

    bool equals(const sp<AudioPortConfig>& other, bool isInput) const;

    status_t writeToParcelable(
            media::audio::common::AudioPortConfig* parcelable, bool isInput) const;
    status_t readFromParcelable(
            const media::audio::common::AudioPortConfig& parcelable, bool isInput);

protected:
    unsigned int mSamplingRate = 0u;
    audio_format_t mFormat = AUDIO_FORMAT_INVALID;
    audio_channel_mask_t mChannelMask = AUDIO_CHANNEL_NONE;
    audio_port_handle_t mId = AUDIO_PORT_HANDLE_NONE;
    struct audio_gain_config mGain = { .index = -1 };
    union audio_io_flags mFlags = { AUDIO_INPUT_FLAG_NONE };
};

} // namespace android
