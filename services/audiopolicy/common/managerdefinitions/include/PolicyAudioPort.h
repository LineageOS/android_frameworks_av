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

#pragma once

#include "AudioCollections.h"
#include "AudioProfileVectorHelper.h"
#include "HandleGenerator.h"
#include <media/AudioGain.h>
#include <media/AudioPort.h>
#include <utils/String8.h>
#include <utils/Vector.h>
#include <utils/RefBase.h>
#include <utils/Errors.h>
#include <system/audio.h>
#include <cutils/config_utils.h>

namespace android {

class HwModule;
class AudioRoute;

class PolicyAudioPort : public virtual RefBase, private HandleGenerator<audio_port_handle_t>
{
public:
    PolicyAudioPort() : mFlags(AUDIO_OUTPUT_FLAG_NONE) {}

    virtual ~PolicyAudioPort() = default;

    virtual const std::string getTagName() const = 0;

    virtual sp<AudioPort> asAudioPort() const = 0;

    virtual void setFlags(uint32_t flags)
    {
        //force direct flag if offload flag is set: offloading implies a direct output stream
        // and all common behaviors are driven by checking only the direct flag
        // this should normally be set appropriately in the policy configuration file
        if (asAudioPort()->getRole() == AUDIO_PORT_ROLE_SOURCE &&
                (flags & AUDIO_OUTPUT_FLAG_COMPRESS_OFFLOAD) != 0) {
            flags |= AUDIO_OUTPUT_FLAG_DIRECT;
        }
        mFlags = flags;
    }
    uint32_t getFlags() const { return mFlags; }

    virtual void attach(const sp<HwModule>& module);
    virtual void detach();
    bool isAttached() { return mModule != 0; }

    // Audio port IDs are in a different namespace than AudioFlinger unique IDs
    static audio_port_handle_t getNextUniqueId();

    // searches for an exact match
    virtual status_t checkExactAudioProfile(const struct audio_port_config *config) const;

    // searches for a compatible match, currently implemented for input
    // parameters are input|output, returned value is the best match.
    status_t checkCompatibleAudioProfile(uint32_t &samplingRate,
                                         audio_channel_mask_t &channelMask,
                                         audio_format_t &format) const
    {
        return checkCompatibleProfile(
                asAudioPort()->getAudioProfiles(), samplingRate, channelMask, format,
                asAudioPort()->getType(), asAudioPort()->getRole());
    }

    void pickAudioProfile(uint32_t &samplingRate,
                          audio_channel_mask_t &channelMask,
                          audio_format_t &format) const;

    static const audio_format_t sPcmFormatCompareTable[];

    static int compareFormats(audio_format_t format1, audio_format_t format2);

    // Used to select an audio HAL output stream with a sample format providing the
    // less degradation for a given AudioTrack sample format.
    static bool isBetterFormatMatch(audio_format_t newFormat,
                                    audio_format_t currentFormat,
                                    audio_format_t targetFormat);
    static uint32_t formatDistance(audio_format_t format1,
                                   audio_format_t format2);
    static const uint32_t kFormatDistanceMax = 4;

    audio_module_handle_t getModuleHandle() const;
    uint32_t getModuleVersionMajor() const;
    const char *getModuleName() const;
    sp<HwModule> getModule() const { return mModule; }

    inline bool isDirectOutput() const
    {
        return (asAudioPort()->getType() == AUDIO_PORT_TYPE_MIX) &&
                (asAudioPort()->getRole() == AUDIO_PORT_ROLE_SOURCE) &&
                (mFlags & (AUDIO_OUTPUT_FLAG_DIRECT | AUDIO_OUTPUT_FLAG_COMPRESS_OFFLOAD));
    }

    inline bool isMmap() const
    {
        return (asAudioPort()->getType() == AUDIO_PORT_TYPE_MIX)
                && (((asAudioPort()->getRole() == AUDIO_PORT_ROLE_SOURCE) &&
                        ((mFlags & AUDIO_OUTPUT_FLAG_MMAP_NOIRQ) != 0))
                    || ((asAudioPort()->getRole() == AUDIO_PORT_ROLE_SINK) &&
                        ((mFlags & AUDIO_INPUT_FLAG_MMAP_NOIRQ) != 0)));
    }

    void addRoute(const sp<AudioRoute> &route) { mRoutes.add(route); }
    const AudioRouteVector &getRoutes() const { return mRoutes; }

private:
    void pickChannelMask(audio_channel_mask_t &channelMask,
                         const ChannelMaskSet &channelMasks) const;
    void pickSamplingRate(uint32_t &rate, const SampleRateSet &samplingRates) const;

    uint32_t mFlags; // attribute flags mask (e.g primary output, direct output...).
    sp<HwModule> mModule;     // audio HW module exposing this I/O stream
    AudioRouteVector mRoutes; // Routes involving this port
};

class PolicyAudioPortConfig : public virtual RefBase
{
public:
    virtual ~PolicyAudioPortConfig() = default;

    virtual sp<PolicyAudioPort> getPolicyAudioPort() const = 0;

    status_t validationBeforeApplyConfig(const struct audio_port_config *config) const;

    void applyPolicyAudioPortConfig(const struct audio_port_config *config) {
        if (config->config_mask & AUDIO_PORT_CONFIG_FLAGS) {
            mFlags = config->flags;
        }
    }

    void toPolicyAudioPortConfig(
            struct audio_port_config *dstConfig,
            const struct audio_port_config *srcConfig = NULL) const;


    virtual bool hasSameHwModuleAs(const sp<PolicyAudioPortConfig>& other) const {
        return (other.get() != nullptr) && (other->getPolicyAudioPort().get() != nullptr) &&
                (getPolicyAudioPort().get() != nullptr) &&
                (other->getPolicyAudioPort()->getModuleHandle() ==
                        getPolicyAudioPort()->getModuleHandle());
    }

    union audio_io_flags mFlags = { AUDIO_INPUT_FLAG_NONE };
};

} // namespace android
