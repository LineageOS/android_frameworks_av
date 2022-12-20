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

#include "effect-impl/EffectContext.h"

#include <audio_utils/ChannelMix.h>

namespace aidl::android::hardware::audio::effect {

using media::audio::common::AudioChannelLayout;
using media::audio::common::AudioDeviceDescription;

enum DownmixState {
    DOWNMIX_STATE_UNINITIALIZED,
    DOWNMIX_STATE_INITIALIZED,
    DOWNMIX_STATE_ACTIVE,
};

class DownmixContext final : public EffectContext {
  public:
    DownmixContext(int statusDepth, const Parameter::Common& common);
    ~DownmixContext();
    RetCode enable();
    RetCode disable();
    void reset();

    RetCode setDmType(Downmix::Type type) {
        mType = type;
        return RetCode::SUCCESS;
    }
    Downmix::Type getDmType() const { return mType; }

    RetCode setVolumeStereo(const Parameter::VolumeStereo& volumeStereo) override {
        // FIXME change volume
        mVolumeStereo = volumeStereo;
        return RetCode::SUCCESS;
    }
    Parameter::VolumeStereo getVolumeStereo() override { return mVolumeStereo; }

    RetCode setOutputDevice(const AudioDeviceDescription& device) override {
        // FIXME change type if playing on headset vs speaker
        mOutputDevice = device;
        return RetCode::SUCCESS;
    }
    AudioDeviceDescription getOutputDevice() { return mOutputDevice; }

    IEffect::Status lvmProcess(float* in, float* out, int samples);

  private:
    DownmixState mState;
    Downmix::Type mType;
    AudioChannelLayout mChMask;
    ::android::audio_utils::channels::ChannelMix mChannelMix;

    // Common Params
    AudioDeviceDescription mOutputDevice;
    Parameter::VolumeStereo mVolumeStereo;

    void init_params(const Parameter::Common& common);
    bool isChannelMaskValid(AudioChannelLayout channelMask);
};

}  // namespace aidl::android::hardware::audio::effect
