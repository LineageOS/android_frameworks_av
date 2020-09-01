/*
 * Copyright (C) 2018 The Android Open Source Project
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

//#define LOG_NDEBUG 0
#include <vector>
#define LOG_TAG "hidl_ClearKeyDrmFactory"
#include <utils/Log.h>

#include <utils/Errors.h>

#include "DrmFactory.h"

#include "DrmPlugin.h"
#include "ClearKeyUUID.h"
#include "MimeType.h"
#include "SessionLibrary.h"

namespace android {
namespace hardware {
namespace drm {
namespace V1_3 {
namespace clearkey {

using ::android::hardware::drm::V1_0::Status;
using ::android::hardware::drm::V1_1::SecurityLevel;
using ::android::hardware::drm::V1_2::clearkey::DrmPlugin;
using ::android::hardware::drm::V1_2::clearkey::SessionLibrary;
using ::android::hardware::Void;

Return<bool> DrmFactory::isCryptoSchemeSupported(
        const hidl_array<uint8_t, 16>& uuid) {
    return clearkeydrm::isClearKeyUUID(uuid.data());
}

Return<bool> DrmFactory::isCryptoSchemeSupported_1_2(const hidl_array<uint8_t, 16>& uuid,
                                                     const hidl_string &mimeType,
                                                     SecurityLevel level) {
    return isCryptoSchemeSupported(uuid) && isContentTypeSupported(mimeType) &&
            level == SecurityLevel::SW_SECURE_CRYPTO;
}

Return<bool> DrmFactory::isContentTypeSupported(const hidl_string &mimeType) {
    // This should match the mimeTypes handed by InitDataParser.
    return mimeType == kIsoBmffVideoMimeType ||
            mimeType == kIsoBmffAudioMimeType ||
            mimeType == kCencInitDataFormat ||
            mimeType == kWebmVideoMimeType ||
            mimeType == kWebmAudioMimeType ||
            mimeType == kWebmInitDataFormat;
}

Return<void> DrmFactory::createPlugin(
    const hidl_array<uint8_t, 16>& uuid,
    const hidl_string& appPackageName,
    createPlugin_cb _hidl_cb) {
    UNUSED(appPackageName);

    DrmPlugin *plugin = NULL;
    if (!isCryptoSchemeSupported(uuid.data())) {
        ALOGE("Clear key Drm HAL: failed to create drm plugin, " \
                "invalid crypto scheme");
        _hidl_cb(Status::BAD_VALUE, plugin);
        return Void();
    }

    plugin = new DrmPlugin(SessionLibrary::get());
    _hidl_cb(Status::OK, plugin);
    return Void();
}

Return<void> DrmFactory::getSupportedCryptoSchemes(
        getSupportedCryptoSchemes_cb _hidl_cb) {
    std::vector<hidl_array<uint8_t, 16>> schemes;
    for (const auto &scheme : clearkeydrm::getSupportedCryptoSchemes()) {
        schemes.push_back(scheme);
    }
    _hidl_cb(schemes);
    return Void();
}

Return<void> DrmFactory::debug(const hidl_handle& fd, const hidl_vec<hidl_string>& /*args*/) {
    if (fd.getNativeHandle() == nullptr || fd->numFds < 1) {
        ALOGE("%s: missing fd for writing", __FUNCTION__);
        return Void();
    }

    FILE* out = fdopen(dup(fd->data[0]), "w");
    uint32_t currentSessions = SessionLibrary::get()->numOpenSessions();
    fprintf(out, "current open sessions: %u\n", currentSessions);
    fclose(out);
    return Void();
}

} // namespace clearkey
} // namespace V1_3
} // namespace drm
} // namespace hardware
} // namespace android
