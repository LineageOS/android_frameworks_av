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

#ifndef CLEARKEY_DRM_FACTORY_H_
#define CLEARKEY_DRM_FACTORY_H_

#include <android/hardware/drm/1.2/IDrmPlugin.h>
#include <android/hardware/drm/1.3/IDrmFactory.h>

#include "ClearKeyTypes.h"

namespace android {
namespace hardware {
namespace drm {
namespace V1_3 {
namespace clearkey {

using ::android::hardware::drm::V1_1::SecurityLevel;
using ::android::hardware::hidl_array;
using ::android::hardware::hidl_handle;
using ::android::hardware::hidl_string;
using ::android::hardware::Return;

struct DrmFactory : public IDrmFactory {
    DrmFactory() {}
    virtual ~DrmFactory() {}

    Return<bool> isCryptoSchemeSupported(const hidl_array<uint8_t, 16>& uuid)
            override;

    Return<bool> isCryptoSchemeSupported_1_2(const hidl_array<uint8_t, 16>& uuid,
                                             const hidl_string& mimeType,
                                             SecurityLevel level) override;

    Return<bool> isContentTypeSupported(const hidl_string &mimeType)
            override;

    Return<void> createPlugin(
            const hidl_array<uint8_t, 16>& uuid,
            const hidl_string& appPackageName,
            createPlugin_cb _hidl_cb) override;

    Return<void> getSupportedCryptoSchemes(
            getSupportedCryptoSchemes_cb _hidl_cb) override;

    Return<void> debug(const hidl_handle& fd, const hidl_vec<hidl_string>& args);

private:
    CLEARKEY_DISALLOW_COPY_AND_ASSIGN(DrmFactory);
};

} // namespace clearkey
} // namespace V1_3
} // namespace drm
} // namespace hardware
} // namespace android

#endif // CLEARKEY_DRM_FACTORY_H_
