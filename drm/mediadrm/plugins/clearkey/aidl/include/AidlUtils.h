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

#include <string>
#include <vector>

#include <android/binder_auto_utils.h>
#include "aidl/android/hardware/drm/Status.h"
#include "ClearKeyTypes.h"

namespace aidl {
namespace android {
namespace hardware {
namespace drm {
namespace clearkey {

inline ::aidl::android::hardware::drm::Status toMockStatus(
        ::aidl::android::hardware::drm::Status status) {
    switch (status) {
        case ::aidl::android::hardware::drm::Status::ERROR_DRM_INSUFFICIENT_SECURITY:
        case ::aidl::android::hardware::drm::Status::ERROR_DRM_FRAME_TOO_LARGE:
        case ::aidl::android::hardware::drm::Status::ERROR_DRM_SESSION_LOST_STATE:
            return ::aidl::android::hardware::drm::Status::ERROR_DRM_UNKNOWN;
        default:
            return status;
    }
}

inline ::ndk::ScopedAStatus toNdkScopedAStatus(::aidl::android::hardware::drm::Status status,
                                               const char* msg = nullptr) {
    if (Status::OK == status) {
        return ::ndk::ScopedAStatus::ok();
    } else {
        auto err = static_cast<int32_t>(status);
        if (msg) {
            return ::ndk::ScopedAStatus::fromServiceSpecificErrorWithMessage(err, msg);
        } else {
            return ::ndk::ScopedAStatus::fromServiceSpecificError(err);
        }
    }
}

inline ::ndk::ScopedAStatus toNdkScopedAStatus(clearkeydrm::CdmResponseType res) {
    return toNdkScopedAStatus(static_cast<::aidl::android::hardware::drm::Status>(res));
}

#define UNUSED(x) (void)(x);

}  // namespace clearkey
}  // namespace drm
}  // namespace hardware
}  // namespace android
}  // namespace aidl
