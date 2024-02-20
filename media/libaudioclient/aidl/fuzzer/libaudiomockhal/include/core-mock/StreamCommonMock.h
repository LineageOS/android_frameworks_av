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
#include <aidl/android/hardware/audio/core/BnStreamCommon.h>

using namespace aidl::android::hardware::audio::core;
using namespace aidl::android::hardware::audio::effect;

namespace aidl::android::hardware::audio::core {

class StreamCommonMock : public BnStreamCommon {
    ndk::ScopedAStatus close() override { return ndk::ScopedAStatus::ok(); }
    ndk::ScopedAStatus prepareToClose() override { return ndk::ScopedAStatus::ok(); }
    ndk::ScopedAStatus updateHwAvSyncId(int32_t) override { return ndk::ScopedAStatus::ok(); }
    ndk::ScopedAStatus getVendorParameters(const std::vector<std::string>&,
                                           std::vector<VendorParameter>*) override {
        return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
    }
    ndk::ScopedAStatus setVendorParameters(const std::vector<VendorParameter>&, bool) override {
        return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
    }
    ndk::ScopedAStatus addEffect(const std::shared_ptr<IEffect>&) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus removeEffect(const std::shared_ptr<IEffect>&) override {
        return ndk::ScopedAStatus::ok();
    }
};

}  // namespace aidl::android::hardware::audio::core
