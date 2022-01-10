/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include <aidl/android/hardware/drm/BnCryptoFactory.h>
#include <aidl/android/hardware/drm/ICryptoFactory.h>
#include <aidl/android/hardware/drm/ICryptoPlugin.h>

#include "ClearKeyTypes.h"

namespace aidl {
namespace android {
namespace hardware {
namespace drm {
namespace clearkey {

struct CryptoFactory : public BnCryptoFactory {
    CryptoFactory() {}
    virtual ~CryptoFactory() {}

    ::ndk::ScopedAStatus createPlugin(
            const ::aidl::android::hardware::drm::Uuid& in_uuid,
            const std::vector<uint8_t>& in_initData,
            std::shared_ptr<::aidl::android::hardware::drm::ICryptoPlugin>* _aidl_return) override;

    ::ndk::ScopedAStatus isCryptoSchemeSupported(
            const ::aidl::android::hardware::drm::Uuid& in_uuid, bool* _aidl_return) override;

  private:
    CLEARKEY_DISALLOW_COPY_AND_ASSIGN(CryptoFactory);
};

}  // namespace clearkey
}  // namespace drm
}  // namespace hardware
}  // namespace android
}  // namespace aidl
