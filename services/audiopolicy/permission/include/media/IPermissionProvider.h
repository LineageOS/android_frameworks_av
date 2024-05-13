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

#pragma once

#include <sys/types.h>

#include <optional>
#include <vector>

#include <com/android/media/permission/PermissionEnum.h>
#include <error/Result.h>

namespace com::android::media::permission {

class IPermissionProvider {
  public:
    // Get all package names which run under a certain app-id. Returns non-empty.
    // Not user specific, since packages are across users. Special app-ids (system,
    // shell, etc.) are handled.  Fails if the provider does not know about the
    // app-id.
    virtual ::android::error::Result<std::vector<std::string>> getPackagesForUid(
            uid_t uid) const = 0;
    // True iff the provided package name runs under the app-id of uid.
    // Special app-ids (system, shell, etc.) are handled.
    // Fails if the provider does not know about the app-id.
    virtual ::android::error::Result<bool> validateUidPackagePair(
            uid_t uid, const std::string& packageName) const = 0;

    // True iff the uid holds the permission (user aware).
    // Fails with NO_INIT if cache hasn't been populated.
    virtual ::android::error::Result<bool> checkPermission(PermissionEnum permission,
                                                           uid_t uid) const = 0;
    virtual ~IPermissionProvider() = default;
};
}  // namespace com::android::media::permission
