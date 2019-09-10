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

#include <media/AudioGain.h>
#include <media/AudioProfile.h>
#include <utils/Errors.h>
#include <utils/RefBase.h>
#include <system/audio.h>
#include <cutils/config_utils.h>

namespace android {

class AudioPortBase : public virtual RefBase
{
public:
    AudioPortBase(const std::string& name, audio_port_type_t type,  audio_port_role_t role) :
            mName(name), mType(type), mRole(role) {}

    virtual ~AudioPortBase() = default;

    void setName(const std::string &name) { mName = name; }
    const std::string &getName() const { return mName; }

    audio_port_type_t getType() const { return mType; }
    audio_port_role_t getRole() const { return mRole; }

    virtual const std::string getTagName() const = 0;

    void setGains(const AudioGains &gains) { mGains = gains; }
    const AudioGains &getGains() const { return mGains; }

    virtual void toAudioPort(struct audio_port *port) const;

    virtual void addAudioProfile(const sp<AudioProfile> &profile) {
        mProfiles.add(profile);
    }
    virtual void clearAudioProfiles() {
        mProfiles.clearProfiles();
    }

    bool hasValidAudioProfile() const { return mProfiles.hasValidProfile(); }

    void setAudioProfiles(const AudioProfileVector &profiles) { mProfiles = profiles; }
    AudioProfileVector &getAudioProfiles() { return mProfiles; }

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

    void dump(std::string *dst, int spaces, bool verbose = true) const;

    AudioGains mGains; // gain controllers
protected:
    std::string  mName;
    audio_port_type_t mType;
    audio_port_role_t mRole;
    AudioProfileVector mProfiles; // AudioProfiles supported by this port (format, Rates, Channels)
};


class AudioPortConfigBase : public virtual RefBase
{
public:
    virtual ~AudioPortConfigBase() = default;

    virtual status_t applyAudioPortConfig(const struct audio_port_config *config,
                                          struct audio_port_config *backupConfig = NULL) = 0;
    virtual void toAudioPortConfig(struct audio_port_config *dstConfig,
                                   const struct audio_port_config *srcConfig = NULL) const = 0;

    unsigned int getSamplingRate() const { return mSamplingRate; }
    audio_format_t getFormat() const { return mFormat; }
    audio_channel_mask_t getChannelMask() const { return mChannelMask; }

protected:
    unsigned int mSamplingRate = 0u;
    audio_format_t mFormat = AUDIO_FORMAT_INVALID;
    audio_channel_mask_t mChannelMask = AUDIO_CHANNEL_NONE;
    struct audio_gain_config mGain = { .index = -1 };
};

} // namespace android
