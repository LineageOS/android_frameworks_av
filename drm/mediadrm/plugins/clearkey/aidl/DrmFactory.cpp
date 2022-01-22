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

::ndk::ScopedAStatus DrmFactory::createPlugin(
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

::ndk::ScopedAStatus DrmFactory::getSupportedCryptoSchemes(vector<Uuid>* _aidl_return) {
    vector<Uuid> schemes;
    Uuid scheme;
    for (const auto& uuid : ::aidl::android::hardware::drm::clearkey::getSupportedCryptoSchemes()) {
        scheme.uuid.assign(uuid.begin(), uuid.end());
        schemes.push_back(scheme);
    }
    *_aidl_return = schemes;
    return ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus DrmFactory::isContentTypeSupported(const string& in_mimeType,
                                                        bool* _aidl_return) {
    // This should match the in_mimeTypes handed by InitDataParser.
    *_aidl_return = in_mimeType == kIsoBmffVideoMimeType || in_mimeType == kIsoBmffAudioMimeType ||
                    in_mimeType == kCencInitDataFormat || in_mimeType == kWebmVideoMimeType ||
                    in_mimeType == kWebmAudioMimeType || in_mimeType == kWebmInitDataFormat;
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus DrmFactory::isCryptoSchemeSupported(const Uuid& in_uuid,
                                                         const string& in_mimeType,
                                                         SecurityLevel in_securityLevel,
                                                         bool* _aidl_return) {
    bool isSupportedMimeType = false;
    if (!isContentTypeSupported(in_mimeType, &isSupportedMimeType).isOk()) {
        ALOGD("%s mime type is not supported by crypto scheme", in_mimeType.c_str());
    }
    *_aidl_return = isClearKeyUUID(in_uuid.uuid.data()) && isSupportedMimeType &&
                    in_securityLevel == SecurityLevel::SW_SECURE_CRYPTO;
    return ::ndk::ScopedAStatus::ok();
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
}  // namespace aidl
