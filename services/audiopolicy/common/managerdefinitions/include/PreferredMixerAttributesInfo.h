/*
 * Copyright (C) 2022 The Android Open Source Project
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

#include <map>

#include <utils/RefBase.h>

#include "AudioRoute.h"
#include "HwModule.h"
#include "IOProfile.h"

namespace android {

class PreferredMixerAttributesInfo : public RefBase {
public:
    PreferredMixerAttributesInfo(uid_t uid, audio_port_handle_t devicePortId,
                                 const sp<IOProfile>& profile, audio_output_flags_t flags,
                                 const audio_mixer_attributes_t& mixerAttributes)
        : mDevicePortId(devicePortId), mUid(uid), mProfile(profile),
          mOutputFlags(flags), mMixerAttributes(mixerAttributes) { }

    audio_port_handle_t getDeviceId() const { return mDevicePortId; }
    const audio_config_base_t& getConfigBase() const { return mMixerAttributes.config; }
    uid_t getUid() const { return mUid; }
    int getActiveClientCount() const { return mActiveClientsCount; }
    const sp<IOProfile> getProfile() const { return mProfile; };
    audio_output_flags_t getFlags() const { return mOutputFlags; }
    const audio_mixer_attributes_t& getMixerAttributes() const { return mMixerAttributes; }

    void increaseActiveClient() { mActiveClientsCount++; }
    void decreaseActiveClient() { mActiveClientsCount--; }
    void resetActiveClient() { mActiveClientsCount = 0; }

    bool isBitPerfect() const {
        return (getFlags() & AUDIO_OUTPUT_FLAG_BIT_PERFECT) != AUDIO_OUTPUT_FLAG_NONE;
    }

    bool configMatches(const audio_config_t& config) const {
        return config.format == mMixerAttributes.config.format &&
                config.channel_mask == mMixerAttributes.config.channel_mask &&
                config.sample_rate == mMixerAttributes.config.sample_rate;
    }

    void dump(String8 *dst);

private:
    const audio_port_handle_t mDevicePortId;
    const uid_t mUid;
    const sp<IOProfile> mProfile;
    const audio_output_flags_t mOutputFlags;
    const audio_mixer_attributes_t mMixerAttributes;
    int mActiveClientsCount = 0;
};

} // namespace android