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
#include <aidl/android/hardware/audio/core/BnBluetoothA2dp.h>

using namespace aidl::android::hardware::audio::core;

namespace aidl::android::hardware::audio::core {

class BluetoothA2dpMock : public BnBluetoothA2dp {
  public:
    ndk::ScopedAStatus isEnabled(bool* _aidl_return) override {
        *_aidl_return = mEnabled;
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus setEnabled(bool enabled) override {
        mEnabled = enabled;
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus supportsOffloadReconfiguration(bool* _aidl_return) override {
        *_aidl_return = kSupportsOffloadReconfiguration;
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus reconfigureOffload(const std::vector<VendorParameter>&) override {
        return ndk::ScopedAStatus::ok();
    }

  private:
    static constexpr bool kSupportsOffloadReconfiguration = true;
    bool mEnabled = false;
};

}  // namespace aidl::android::hardware::audio::core
