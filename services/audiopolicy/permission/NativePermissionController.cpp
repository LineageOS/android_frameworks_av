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

#include <media/NativePermissionController.h>

#include <algorithm>
#include <optional>
#include <utility>

#include <android-base/expected.h>
#include <cutils/android_filesystem_config.h>
#include <utils/Errors.h>

using ::android::base::unexpected;
using ::android::binder::Status;
using ::android::error::Result;

namespace com::android::media::permission {
static std::optional<std::string> getFixedPackageName(uid_t uid) {
    // These values are in sync with AppOpsService
    switch (uid % AID_USER_OFFSET) {
        case AID_ROOT:
            return "root";
        case AID_SYSTEM:
            return "system";
        case AID_SHELL:
            return "shell";
        case AID_MEDIA:
            return "media";
        case AID_AUDIOSERVER:
            return "audioserver";
        case AID_CAMERASERVER:
            return "cameraserver";
        // These packages are not handled by AppOps, but labeling may be useful for us
        case AID_RADIO:
            return "telephony";
        case AID_BLUETOOTH:
            return "bluetooth";
        default:
            return std::nullopt;
    }
}

// -- Begin Binder methods
Status NativePermissionController::populatePackagesForUids(
        const std::vector<UidPackageState>& initialPackageStates) {
    std::lock_guard l{m_};
    if (!is_package_populated_) is_package_populated_ = true;
    package_map_.clear();
    std::transform(initialPackageStates.begin(), initialPackageStates.end(),
                   std::inserter(package_map_, package_map_.end()),
                   [](const auto& x) -> std::pair<uid_t, std::vector<std::string>> {
                       return {x.uid, x.packageNames};
                   });
    std::erase_if(package_map_, [](const auto& x) { return x.second.empty(); });
    return Status::ok();
}

Status NativePermissionController::updatePackagesForUid(const UidPackageState& newPackageState) {
    std::lock_guard l{m_};
    package_map_.insert_or_assign(newPackageState.uid, newPackageState.packageNames);
    const auto& cursor = package_map_.find(newPackageState.uid);

    if (newPackageState.packageNames.empty()) {
        if (cursor != package_map_.end()) {
            package_map_.erase(cursor);
        }
    } else {
        if (cursor != package_map_.end()) {
            cursor->second = newPackageState.packageNames;
        } else {
            package_map_.insert({newPackageState.uid, newPackageState.packageNames});
        }
    }
    return Status::ok();
}

Status NativePermissionController::populatePermissionState(PermissionEnum perm,
                                                           const std::vector<int>& uids) {
    if (perm >= PermissionEnum::ENUM_SIZE || static_cast<int>(perm) < 0) {
        return Status::fromExceptionCode(Status::EX_ILLEGAL_ARGUMENT);
    }
    std::lock_guard l{m_};
    auto& cursor = permission_map_[static_cast<size_t>(perm)];
    cursor = std::vector<uid_t>{uids.begin(), uids.end()};
    // should be sorted
    std::sort(cursor.begin(), cursor.end());
    return Status::ok();
}

// -- End Binder methods

Result<std::vector<std::string>> NativePermissionController::getPackagesForUid(uid_t uid) const {
    uid = uid % AID_USER_OFFSET;
    const auto fixed_package_opt = getFixedPackageName(uid);
    if (fixed_package_opt.has_value()) {
        return Result<std::vector<std::string>>{std::in_place_t{}, {fixed_package_opt.value()}};
    }
    std::lock_guard l{m_};
    if (!is_package_populated_) return unexpected{::android::NO_INIT};
    const auto cursor = package_map_.find(uid);
    if (cursor != package_map_.end()) {
        return cursor->second;
    } else {
        return unexpected{::android::BAD_VALUE};
    }
}

Result<bool> NativePermissionController::validateUidPackagePair(
        uid_t uid, const std::string& packageName) const {
    uid = uid % AID_USER_OFFSET;
    const auto fixed_package_opt = getFixedPackageName(uid);
    if (fixed_package_opt.has_value()) {
        return packageName == fixed_package_opt.value();
    }
    std::lock_guard l{m_};
    if (!is_package_populated_) return unexpected{::android::NO_INIT};
    const auto cursor = package_map_.find(uid);
    return (cursor != package_map_.end()) &&
           (std::find(cursor->second.begin(), cursor->second.end(), packageName) !=
            cursor->second.end());
}

Result<bool> NativePermissionController::checkPermission(PermissionEnum perm, uid_t uid) const {
    std::lock_guard l{m_};
    const auto& uids = permission_map_[static_cast<size_t>(perm)];
    if (!uids.empty()) {
        return std::binary_search(uids.begin(), uids.end(), uid);
    } else {
        return unexpected{::android::NO_INIT};
    }
}

}  // namespace com::android::media::permission
