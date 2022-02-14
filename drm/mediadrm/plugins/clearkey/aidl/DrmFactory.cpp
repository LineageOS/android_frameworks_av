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
#define LOG_TAG "clearkey-DrmFactory"

#include <utils/Log.h>

#include "DrmFactory.h"

#include "ClearKeyUUID.h"
#include "CryptoPlugin.h"
#include "DrmPlugin.h"
#include "MimeTypeStdStr.h"
#include "SessionLibrary.h"
#include "AidlUtils.h"

namespace aidl {
namespace android {
namespace hardware {
namespace drm {
namespace clearkey {

using std::string;
using std::vector;

using ::aidl::android::hardware::drm::SecurityLevel;
using ::aidl::android::hardware::drm::Status;
using ::aidl::android::hardware::drm::Uuid;

::ndk::ScopedAStatus DrmFactory::createDrmPlugin(
        const Uuid& in_uuid, const string& in_appPackageName,
        std::shared_ptr<::aidl::android::hardware::drm::IDrmPlugin>* _aidl_return) {
    UNUSED(in_appPackageName);

    if (!isClearKeyUUID(in_uuid.uuid.data())) {
        ALOGE("Clearkey Drm HAL: failed to create drm plugin, "
              "invalid crypto scheme");
        *_aidl_return = nullptr;
        return toNdkScopedAStatus(Status::BAD_VALUE);
    }

    std::shared_ptr<DrmPlugin> plugin =
            ::ndk::SharedRefBase::make<DrmPlugin>(SessionLibrary::get());
    *_aidl_return = plugin;
    return toNdkScopedAStatus(Status::OK);
}

::ndk::ScopedAStatus DrmFactory::createCryptoPlugin(
        const Uuid& in_uuid, const std::vector<uint8_t>& in_initData,
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

::ndk::ScopedAStatus DrmFactory::getSupportedCryptoSchemes(CryptoSchemes* _aidl_return) {
    CryptoSchemes schemes{};
    for (const auto& uuid : ::aidl::android::hardware::drm::clearkey::getSupportedCryptoSchemes()) {
        schemes.uuids.push_back({uuid});
    }
    for (auto mime : {kIsoBmffVideoMimeType, kIsoBmffAudioMimeType, kCencInitDataFormat,
                      kWebmVideoMimeType, kWebmAudioMimeType, kWebmInitDataFormat}) {
        const auto minLevel = SecurityLevel::SW_SECURE_CRYPTO;
        const auto maxLevel = SecurityLevel::SW_SECURE_CRYPTO;
        schemes.mimeTypes.push_back({mime, minLevel, maxLevel});
    }
    *_aidl_return = schemes;
    return ndk::ScopedAStatus::ok();
}

binder_status_t DrmFactory::dump(int fd, const char** args, uint32_t numArgs) {
    UNUSED(args);
    UNUSED(numArgs);

    if (fd < 0) {
        ALOGE("%s: negative fd", __FUNCTION__);
        return STATUS_BAD_VALUE;
    }

    uint32_t currentSessions = SessionLibrary::get()->numOpenSessions();
    dprintf(fd, "current open sessions: %u\n", currentSessions);

    return STATUS_OK;
}

}  // namespace clearkey
}  // namespace drm
}  // namespace hardware
}  // namespace android
} // namespace aidl
