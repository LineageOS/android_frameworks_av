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
#include <aidl/android/hardware/audio/core/sounddose/BnSoundDose.h>

using namespace aidl::android::hardware::audio::core::sounddose;

namespace aidl::android::hardware::audio::core::sounddose {

class SoundDoseMock : public BnSoundDose {
    ndk::ScopedAStatus setOutputRs2UpperBound(float in_rs2ValueDbA) override {
        mOutputRs2UpperBound = in_rs2ValueDbA;
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus getOutputRs2UpperBound(float* _aidl_return) override {
        *_aidl_return = mOutputRs2UpperBound;
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus registerSoundDoseCallback(
            const std::shared_ptr<ISoundDose::IHalSoundDoseCallback>&) override {
        return ndk::ScopedAStatus::ok();
    }

  private:
    float mOutputRs2UpperBound;
};

}  // namespace aidl::android::hardware::audio::core::sounddose
