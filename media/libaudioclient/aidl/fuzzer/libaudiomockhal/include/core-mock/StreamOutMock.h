/*
 * Copyright (C) 2024 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
#include <aidl/android/hardware/audio/core/BnStreamOut.h>

using namespace aidl::android::hardware::audio::common;
using namespace aidl::android::hardware::audio::core;
using namespace aidl::android::media::audio::common;

namespace aidl::android::hardware::audio::core {

class StreamOutMock : public BnStreamOut {
    ndk::ScopedAStatus getStreamCommon(std::shared_ptr<IStreamCommon>* _aidl_return) override;
    ndk::ScopedAStatus getHwVolume(std::vector<float>* _aidl_return) override;
    ndk::ScopedAStatus setHwVolume(const std::vector<float>& in_channelVolumes) override;
    ndk::ScopedAStatus getAudioDescriptionMixLevel(float* _aidl_return) override;
    ndk::ScopedAStatus setAudioDescriptionMixLevel(float in_leveldB) override;
    ndk::ScopedAStatus getDualMonoMode(AudioDualMonoMode* _aidl_return) override;
    ndk::ScopedAStatus setDualMonoMode(AudioDualMonoMode in_mode) override;
    ndk::ScopedAStatus getPlaybackRateParameters(AudioPlaybackRate* _aidl_return) override;
    ndk::ScopedAStatus setPlaybackRateParameters(const AudioPlaybackRate& in_playbackRate) override;

    ndk::ScopedAStatus updateMetadata(const SourceMetadata&) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus updateOffloadMetadata(const AudioOffloadMetadata&) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus getRecommendedLatencyModes(std::vector<AudioLatencyMode>*) override {
        return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
    }
    ndk::ScopedAStatus setLatencyMode(AudioLatencyMode) override {
        return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
    }
    ndk::ScopedAStatus selectPresentation(int32_t, int32_t) override {
        return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
    }

  private:
    AudioPlaybackRate mPlaybackRateParameters;
    AudioDualMonoMode mDualMonoMode;
    float mAudioDescriptionMixLeveldB;
    std::vector<float> mHwVolume;
    std::shared_ptr<IStreamCommon> mStreamCommon;
};

}  // namespace aidl::android::hardware::audio::core
