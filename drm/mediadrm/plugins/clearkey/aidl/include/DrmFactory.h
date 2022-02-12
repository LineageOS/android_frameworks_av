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

#include <aidl/android/hardware/drm/BnDrmFactory.h>
#include <aidl/android/hardware/drm/IDrmFactory.h>
#include <aidl/android/hardware/drm/IDrmPlugin.h>
#include <aidl/android/hardware/drm/ICryptoPlugin.h>

#include <string>
#include <vector>

#include "ClearKeyTypes.h"

namespace aidl {
namespace android {
namespace hardware {
namespace drm {
namespace clearkey {

struct DrmFactory : public BnDrmFactory {
    DrmFactory() {}
    virtual ~DrmFactory() {}

    ::ndk::ScopedAStatus createDrmPlugin(
            const ::aidl::android::hardware::drm::Uuid& in_uuid,
            const std::string& in_appPackageName,
            std::shared_ptr<::aidl::android::hardware::drm::IDrmPlugin>* _aidl_return) override;

    ::ndk::ScopedAStatus createCryptoPlugin(
            const ::aidl::android::hardware::drm::Uuid& in_uuid,
            const std::vector<uint8_t>& in_initData,
            std::shared_ptr<::aidl::android::hardware::drm::ICryptoPlugin>* _aidl_return) override;

    ::ndk::ScopedAStatus getSupportedCryptoSchemes(
            ::aidl::android::hardware::drm::CryptoSchemes* _aidl_return) override;

    binder_status_t dump(int fd, const char** args, uint32_t numArgs) override;


  private:
    CLEARKEY_DISALLOW_COPY_AND_ASSIGN(DrmFactory);
};

}  // namespace clearkey
}  // namespace drm
}  // namespace hardware
}  // namespace android
}  // namespace aidl
