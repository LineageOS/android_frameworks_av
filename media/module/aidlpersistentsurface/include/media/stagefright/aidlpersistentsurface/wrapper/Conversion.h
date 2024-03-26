/*
 * Copyright 2024, The Android Open Source Project
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

#include <android/binder_auto_utils.h>
#include <ui/GraphicBuffer.h>
#include <utils/Errors.h>

#include <aidl/android/hardware/graphics/common/Dataspace.h>
#include <aidl/android/hardware/graphics/common/PixelFormat.h>
#include <aidl/android/media/AidlColorAspects.h>

namespace android::media::aidl_conversion {

inline status_t fromAidlStatus(const ::ndk::ScopedAStatus &status) {
    if (!status.isOk()) {
        if (status.getExceptionCode() == EX_SERVICE_SPECIFIC) {
            return static_cast<status_t>(status.getServiceSpecificError());
        } else {
            return static_cast<status_t>(FAILED_TRANSACTION);
        }
    }
   return NO_ERROR;
}

inline ::ndk::ScopedAStatus toAidlStatus(status_t status) {
    if (status == NO_ERROR) {
        return ::ndk::ScopedAStatus::ok();
    }
    return ::ndk::ScopedAStatus::fromServiceSpecificError(status);
}

inline int32_t compactFromAidlColorAspects(::aidl::android::media::AidlColorAspects const& s) {
    return static_cast<int32_t>(
            (static_cast<uint32_t>(s.range) << 24) |
            (static_cast<uint32_t>(s.primaries) << 16) |
            (static_cast<uint32_t>(s.transfer)) |
            (static_cast<uint32_t>(s.matrixCoeffs) << 8));
}

inline int32_t rawFromAidlDataspace(
        ::aidl::android::hardware::graphics::common::Dataspace const& s) {
    return static_cast<int32_t>(s);
}

}  // namespace android::media::aidl_conversion
