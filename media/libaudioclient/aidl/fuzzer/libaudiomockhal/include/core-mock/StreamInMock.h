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
#include <aidl/android/hardware/audio/core/BnStreamIn.h>

using namespace aidl::android::hardware::audio::common;
using namespace aidl::android::hardware::audio::core;
using namespace aidl::android::media::audio::common;

namespace aidl::android::hardware::audio::core {

class StreamInMock : public BnStreamIn {
    ndk::ScopedAStatus getStreamCommon(std::shared_ptr<IStreamCommon>* _aidl_return) override;
    ndk::ScopedAStatus getMicrophoneDirection(
            IStreamIn::MicrophoneDirection* _aidl_return) override;
    ndk::ScopedAStatus setMicrophoneDirection(IStreamIn::MicrophoneDirection in_direction) override;
    ndk::ScopedAStatus getMicrophoneFieldDimension(float* _aidl_return) override;
    ndk::ScopedAStatus setMicrophoneFieldDimension(float in_zoom) override;
    ndk::ScopedAStatus getHwGain(std::vector<float>* _aidl_return) override;
    ndk::ScopedAStatus setHwGain(const std::vector<float>& in_channelGains) override;

    ndk::ScopedAStatus getActiveMicrophones(std::vector<MicrophoneDynamicInfo>*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus updateMetadata(const SinkMetadata&) override {
        return ndk::ScopedAStatus::ok();
    }

  private:
    IStreamIn::MicrophoneDirection mMicrophoneDirection;
    float mMicrophoneFieldDimension;
    std::vector<float> mHwGains;
    std::shared_ptr<IStreamCommon> mStreamCommon;
};

}  // namespace aidl::android::hardware::audio::core
