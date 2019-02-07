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

#include "DeviceDescriptor.h"
#include <utils/RefBase.h>
#include <media/AudioPolicy.h>
#include <utils/KeyedVector.h>
#include <system/audio.h>
#include <utils/String8.h>

#include <DeviceDescriptor.h>
#include <AudioOutputDescriptor.h>

namespace android {

/**
 * custom mix entry in mPolicyMixes
 */
class AudioPolicyMix : public RefBase {
public:
    AudioPolicyMix() {}

    const sp<SwAudioOutputDescriptor> &getOutput() const;

    void setOutput(sp<SwAudioOutputDescriptor> &output);

    void clearOutput();

    android::AudioMix *getMix();

    void setMix(AudioMix &mix);

    void dump(String8 *dst, int spaces, int index) const;

private:
    AudioMix    mMix;                   // Audio policy mix descriptor
    sp<SwAudioOutputDescriptor> mOutput;  // Corresponding output stream
};


class AudioPolicyMixCollection : public DefaultKeyedVector<String8, sp<AudioPolicyMix> >
{
public:
    status_t getAudioPolicyMix(const String8& address, sp<AudioPolicyMix> &policyMix) const;

    status_t registerMix(const String8& address, AudioMix mix, sp<SwAudioOutputDescriptor> desc);

    status_t unregisterMix(const String8& address);

    void closeOutput(sp<SwAudioOutputDescriptor> &desc);

    /**
     * Try to find an output descriptor for the given attributes.
     *
     * @param[in] attributes to consider fowr the research of output descriptor.
     * @param[out] desc to return if an primary output could be found.
     * @param[out] secondaryDesc other desc that the audio should be routed to.
     */
    status_t getOutputForAttr(audio_attributes_t attributes, uid_t uid,
                sp<SwAudioOutputDescriptor> &primaryDesc,
                std::vector<sp<SwAudioOutputDescriptor>> *secondaryDescs);

    sp<DeviceDescriptor> getDeviceAndMixForInputSource(audio_source_t inputSource,
                                                       const DeviceVector &availableDeviceTypes,
                                                       AudioMix **policyMix) const;

    /**
     * @brief try to find a matching mix for a given output descriptor and returns the associated
     * output device.
     * @param output to be considered
     * @param availableOutputDevices list of output devices currently reachable
     * @param policyMix to be returned if any mix matching ouput descriptor
     * @return device selected from the mix attached to the output, null pointer otherwise
     */
    sp<DeviceDescriptor> getDeviceAndMixForOutput(const sp<SwAudioOutputDescriptor> &output,
                                                  const DeviceVector &availableOutputDevices,
                                                  AudioMix **policyMix = nullptr);

    status_t getInputMixForAttr(audio_attributes_t attr, AudioMix **policyMix);

    status_t setUidDeviceAffinities(uid_t uid, const Vector<AudioDeviceTypeAddr>& devices);
    status_t removeUidDeviceAffinities(uid_t uid);
    status_t getDevicesForUid(uid_t uid, Vector<AudioDeviceTypeAddr>& devices) const;

    void dump(String8 *dst) const;

private:
    enum class MixMatchStatus { MATCH, NO_MATCH, INVALID_MIX };
    MixMatchStatus mixMatch(const AudioMix* mix, size_t mixIndex,
                            audio_attributes_t attributes, uid_t uid);
};

} // namespace android
