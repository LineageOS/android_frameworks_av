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
#include "core-mock/StreamOutMock.h"
#include "core-mock/StreamCommonMock.h"

namespace aidl::android::hardware::audio::core {

ndk::ScopedAStatus StreamOutMock::getStreamCommon(std::shared_ptr<IStreamCommon>* _aidl_return) {
    if (!mStreamCommon) {
        mStreamCommon = ndk::SharedRefBase::make<StreamCommonMock>();
    }
    *_aidl_return = mStreamCommon;
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus StreamOutMock::getHwVolume(std::vector<float>* _aidl_return) {
    *_aidl_return = mHwVolume;
    return ndk::ScopedAStatus::ok();
}
ndk::ScopedAStatus StreamOutMock::setHwVolume(const std::vector<float>& in_channelVolumes) {
    mHwVolume = in_channelVolumes;
    return ndk::ScopedAStatus::ok();
}
ndk::ScopedAStatus StreamOutMock::getAudioDescriptionMixLevel(float* _aidl_return) {
    *_aidl_return = mAudioDescriptionMixLeveldB;
    return ndk::ScopedAStatus::ok();
}
ndk::ScopedAStatus StreamOutMock::setAudioDescriptionMixLevel(float in_leveldB) {
    mAudioDescriptionMixLeveldB = in_leveldB;
    return ndk::ScopedAStatus::ok();
}
ndk::ScopedAStatus StreamOutMock::getDualMonoMode(AudioDualMonoMode* _aidl_return) {
    *_aidl_return = mDualMonoMode;
    return ndk::ScopedAStatus::ok();
}
ndk::ScopedAStatus StreamOutMock::setDualMonoMode(AudioDualMonoMode in_mode) {
    mDualMonoMode = in_mode;
    return ndk::ScopedAStatus::ok();
}
ndk::ScopedAStatus StreamOutMock::getPlaybackRateParameters(AudioPlaybackRate* _aidl_return) {
    *_aidl_return = mPlaybackRateParameters;
    return ndk::ScopedAStatus::ok();
}
ndk::ScopedAStatus StreamOutMock::setPlaybackRateParameters(
        const AudioPlaybackRate& in_playbackRate) {
    mPlaybackRateParameters = in_playbackRate;
    return ndk::ScopedAStatus::ok();
}

}  // namespace aidl::android::hardware::audio::core
