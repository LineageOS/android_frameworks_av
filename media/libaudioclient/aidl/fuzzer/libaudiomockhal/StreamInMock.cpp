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
#include "core-mock/StreamInMock.h"
#include "core-mock/StreamCommonMock.h"

namespace aidl::android::hardware::audio::core {

ndk::ScopedAStatus StreamInMock::getStreamCommon(std::shared_ptr<IStreamCommon>* _aidl_return) {
    if (!mStreamCommon) {
        mStreamCommon = ndk::SharedRefBase::make<StreamCommonMock>();
    }
    *_aidl_return = mStreamCommon;
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus StreamInMock::getMicrophoneDirection(
        IStreamIn::MicrophoneDirection* _aidl_return) {
    *_aidl_return = mMicrophoneDirection;
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus StreamInMock::setMicrophoneDirection(
        IStreamIn::MicrophoneDirection in_direction) {
    mMicrophoneDirection = in_direction;
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus StreamInMock::getMicrophoneFieldDimension(float* _aidl_return) {
    *_aidl_return = mMicrophoneFieldDimension;
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus StreamInMock::setMicrophoneFieldDimension(float in_zoom) {
    mMicrophoneFieldDimension = in_zoom;
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus StreamInMock::getHwGain(std::vector<float>* _aidl_return) {
    *_aidl_return = mHwGains;
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus StreamInMock::setHwGain(const std::vector<float>& in_channelGains) {
    mHwGains = in_channelGains;
    return ndk::ScopedAStatus::ok();
}

}  // namespace aidl::android::hardware::audio::core
