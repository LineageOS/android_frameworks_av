/*
 * Copyright (C) 2023 The Android Open Source Project
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

#define LOG_TAG "Permission"
//#define LOG_NDEBUG 0

#include "Permission.h"

#include <binder/PermissionController.h>
#include <media/AidlConversionCppNdk.h>
#include <utils/Log.h>

namespace android::afutils {

// TODO b/182392769: use attribution source util
content::AttributionSourceState checkAttributionSourcePackage(
        const content::AttributionSourceState& attributionSource) {
    Vector<String16> packages;
    PermissionController{}.getPackagesForUid(attributionSource.uid, packages);

    content::AttributionSourceState checkedAttributionSource = attributionSource;
    if (!attributionSource.packageName.has_value()
            || attributionSource.packageName.value().size() == 0) {
        if (!packages.isEmpty()) {
            checkedAttributionSource.packageName =
                std::move(legacy2aidl_String16_string(packages[0]).value());
        }
    } else {
        const String16 opPackageLegacy = VALUE_OR_FATAL(
                aidl2legacy_string_view_String16(attributionSource.packageName.value_or("")));
        if (std::find_if(packages.begin(), packages.end(),
                [&opPackageLegacy](const auto& package) {
                return opPackageLegacy == package; }) == packages.end()) {
            ALOGW("The package name(%s) provided does not correspond to the uid %d",
                    attributionSource.packageName.value_or("").c_str(), attributionSource.uid);
        }
    }
    return checkedAttributionSource;
}

}  // namespace android::afutils
