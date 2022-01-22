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
#define LOG_TAG "clearkey-CryptoFactory"
#include <utils/Log.h>

#include "CryptoFactory.h"

#include "ClearKeyUUID.h"
#include "CryptoPlugin.h"
#include "AidlUtils.h"

namespace aidl {
namespace android {
namespace hardware {
namespace drm {
namespace clearkey {

using ::aidl::android::hardware::drm::Status;
using ::aidl::android::hardware::drm::Uuid;

using std::vector;

::ndk::ScopedAStatus CryptoFactory::createPlugin(
        const ::aidl::android::hardware::drm::Uuid& in_uuid,
        const std::vector<uint8_t>& in_initData,
        std::shared_ptr<::aidl::android::hardware::drm::ICryptoPlugin>* _aidl_return) {
    if (!isClearKeyUUID(in_uuid.uuid.data())) {
        ALOGE("Clearkey Drm HAL: failed to create crypto plugin, "
              "invalid crypto scheme");
        *_aidl_return = nullptr;
        return toNdkScopedAStatus(Status::BAD_VALUE);
    }

    std::shared_ptr<CryptoPlugin> plugin = ::ndk::SharedRefBase::make<CryptoPlugin>(in_initData);
    Status status = plugin->getInitStatus();
    if (status != Status::OK) {
        plugin.reset();
        plugin = nullptr;
    }
    *_aidl_return = plugin;
    return toNdkScopedAStatus(status);
}

::ndk::ScopedAStatus CryptoFactory::isCryptoSchemeSupported(const Uuid& in_uuid,
                                                            bool* _aidl_return) {
    *_aidl_return = isClearKeyUUID(in_uuid.uuid.data());
    return ::ndk::ScopedAStatus::ok();
}

}  // namespace clearkey
}  // namespace drm
}  // namespace hardware
}  // namespace android
}  // namespace aidl
