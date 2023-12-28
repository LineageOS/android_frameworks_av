/*
 * Copyright (C) 2024 The Android Open Source Project
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

#include "Utils.h"
#include <android-base/properties.h>
#include <com_android_internal_camera_flags.h>


namespace android {

using namespace com::android::internal::camera::flags;

constexpr const char *LEGACY_VNDK_VERSION_PROP = "ro.vndk.version";
constexpr const char *BOARD_API_LEVEL_PROP = "ro.board.api_level";
constexpr int MAX_VENDOR_API_LEVEL = 1000000;
constexpr int FIRST_VNDK_VERSION = 202404;

int getVNDKVersionFromProp(int defaultVersion) {
    if (!com_android_internal_camera_flags_use_ro_board_api_level_for_vndk_version()) {
        return base::GetIntProperty(LEGACY_VNDK_VERSION_PROP, defaultVersion);
    }

    int vndkVersion = base::GetIntProperty(BOARD_API_LEVEL_PROP, MAX_VENDOR_API_LEVEL);

    if (vndkVersion == MAX_VENDOR_API_LEVEL) {
        // Couldn't find property
        return defaultVersion;
    }

    if (vndkVersion < __ANDROID_API_V__) {
        // VNDK versions below V return the corresponding SDK version.
        return vndkVersion;
    }

    // VNDK for Android V and above are of the format YYYYMM starting with 202404 and is bumped
    // up once a year. So V would be 202404 and the next one would be 202504.
    // This is the same assumption as that made in system/core/init/property_service.cpp.
    vndkVersion = (vndkVersion - FIRST_VNDK_VERSION) / 100;
    return __ANDROID_API_V__ + vndkVersion;
}

} // namespace android
