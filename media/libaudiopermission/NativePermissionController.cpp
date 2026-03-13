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

// #define LOG_NDEBUG 0
#define LOG_TAG "NativePermissionController"

#include <media/NativePermissionController.h>

#include <algorithm>
#include <optional>
#include <utility>

#include <android-base/expected.h>
#include <cutils/android_filesystem_config.h>
#include <utils/Errors.h>
#include <utils/Log.h>

using ::android::binder::Status;
using ::android::error::BinderResult;
using ::android::error::unexpectedExceptionCode;

namespace com::android::media::permission {
static std::optional<std::string> getFixedPackageName(uid_t uid) {
    // These values are in sync with AppOpsService
    switch (uid % AID_USER_OFFSET) {
        case AID_ROOT:
            return "root";
        case AID_SYSTEM:
            return "android";
        case AID_SHELL:
            return "com.android.shell";
        case AID_MEDIA:
            return "media";
        case AID_AUDIOSERVER:
            return "audioserver";
        case AID_CAMERASERVER:
            return "cameraserver";
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
                   [](const auto& x)
                           -> std::pair<uid_t, std::vector<UidPackageState::PackageState>> {
                       return {x.uid, x.packageStates};
                   });
    std::erase_if(package_map_, [](const auto& x) { return x.second.empty(); });
    return Status::ok();
}

Status NativePermissionController::updatePackagesForUid(const UidPackageState& newPackageState) {
    std::lock_guard l{m_};
    ALOGD("%s, %s", __func__, newPackageState.toString().c_str());
    package_map_.insert_or_assign(newPackageState.uid, newPackageState.packageStates);
    const auto& cursor = package_map_.find(newPackageState.uid);

    if (newPackageState.packageStates.empty()) {
        if (cursor != package_map_.end()) {
            package_map_.erase(cursor);
        }
    } else {
        if (cursor != package_map_.end()) {
            cursor->second = newPackageState.packageStates;
        } else {
            package_map_.insert({newPackageState.uid, newPackageState.packageStates});
        }
    }
    return Status::ok();
}

Status NativePermissionController::populatePermissionState(PermissionEnum perm,
                                                           const std::vector<int>& uids) {
    ALOGV("%s, %d", __func__, static_cast<int>(perm));
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

BinderResult<std::vector<std::string>> NativePermissionController::getPackagesForUid(
        uid_t uid) const {
    uid = uid % AID_USER_OFFSET;
    const auto fixed_package_opt = getFixedPackageName(uid);
    if (fixed_package_opt.has_value()) {
        return BinderResult<std::vector<std::string>>{std::in_place_t{},
                                                      {fixed_package_opt.value()}};
    }
    std::lock_guard l{m_};
    if (!is_package_populated_) {
        return unexpectedExceptionCode(
                Status::EX_ILLEGAL_STATE,
                "NPC::getPackagesForUid: controller never populated by system_server");
    }
    const auto cursor = package_map_.find(uid);
    if (cursor != package_map_.end()) {
        std::vector<std::string> package_names;
        std::transform(cursor->second.begin(), cursor->second.end(),
                       std::back_inserter(package_names),
                       [](const auto& x) { return x.packageName; });
        return package_names;
    } else {
        return unexpectedExceptionCode(
                Status::EX_ILLEGAL_ARGUMENT,
                ("NPC::getPackagesForUid: uid not found: " + std::to_string(uid)).c_str());
    }
}

BinderResult<bool> NativePermissionController::validateUidPackagePair(
        uid_t uid, const std::string& packageName) const {
    if (uid == AID_ROOT || uid == AID_SYSTEM) return true;
    uid = uid % AID_USER_OFFSET;
    const auto fixed_package_opt = getFixedPackageName(uid);
    if (fixed_package_opt.has_value()) {
        return (uid == AID_ROOT || uid == AID_SYSTEM) ? true
                                                      : packageName == fixed_package_opt.value();
    }
    std::lock_guard l{m_};
    if (!is_package_populated_) {
        return unexpectedExceptionCode(
                Status::EX_ILLEGAL_STATE,
                "NPC::validatedUidPackagePair: controller never populated by system_server");
    }
    const auto cursor = package_map_.find(uid);
    if (cursor == package_map_.end()) {
        return unexpectedExceptionCode(Status::EX_ILLEGAL_ARGUMENT,
                                      ("NPC::validateUidPackagePair: uid not found: " +
                                        std::to_string(uid) + " for package " + packageName)
                                               .c_str());
    }
    return std::any_of(cursor->second.begin(), cursor->second.end(),
                       [&](const auto& x) { return x.packageName == packageName; });
}

BinderResult<bool> NativePermissionController::checkPermission(PermissionEnum perm,
                                                               uid_t uid) const {
    if (uid == AID_ROOT || uid == AID_SYSTEM || uid == getuid()) return true;
    std::lock_guard l{m_};
    const auto& uids = permission_map_[static_cast<size_t>(perm)];
    if (!uids.empty()) {
        const bool ret = std::binary_search(uids.begin(), uids.end(), uid);
        // Log locally until all call-sites log errors well
        ALOGV_IF(!ret, "%s: missing %d for %u", __func__, static_cast<int>(perm), uid);
        return ret;
    } else {
        return unexpectedExceptionCode(
                Status::EX_ILLEGAL_STATE,
                "NPC::checkPermission: controller never populated by system_server");
    }
}

BinderResult<int32_t> NativePermissionController::getHighestTargetSdkForUid(uid_t uid) const {
    uid = uid % AID_USER_OFFSET;
    std::lock_guard l{m_};
    if (!is_package_populated_) {
        return unexpectedExceptionCode(
                Status::EX_ILLEGAL_STATE,
                "NPC::getHighestTargetSdkForUid: controller never populated by system_server");
    }
    const auto cursor = package_map_.find(uid);
    if (cursor != package_map_.end()) {
        if (cursor->second.empty()) {
            return unexpectedExceptionCode(
                    Status::EX_ILLEGAL_STATE,
                    ("NPC::getHighestTargetSdkForUid: empty package list for uid: " +
                     std::to_string(uid))
                            .c_str());
        }
        const auto max_it = std::max_element(
                cursor->second.begin(), cursor->second.end(),
                [](const auto& a, const auto& b) { return a.targetSdk < b.targetSdk; });
        return max_it->targetSdk;
    } else {
        return unexpectedExceptionCode(
                Status::EX_ILLEGAL_ARGUMENT,
                ("NPC::getHighestTargetSdkForUid: uid not found: " + std::to_string(uid)).c_str());
    }
}

BinderResult<bool> NativePermissionController::doesUidPermitPlaybackCapture(uid_t uid) const {
    uid = uid % AID_USER_OFFSET;
    std::lock_guard l{m_};
    if (!is_package_populated_) {
        return unexpectedExceptionCode(
                Status::EX_ILLEGAL_STATE,
                "NPC::doesUidPermitPlaybackCapture: controller never populated by system_server");
    }
    const auto cursor = package_map_.find(uid);
    if (cursor != package_map_.end()) {
        if (cursor->second.empty()) {
            return unexpectedExceptionCode(
                    Status::EX_ILLEGAL_STATE,
                    ("NPC::doesUidPermitPlaybackCapture: empty package list for uid: " +
                     std::to_string(uid))
                            .c_str());
        }
        return std::all_of(cursor->second.begin(), cursor->second.end(),
                           [](const auto& x) { return x.isPlaybackCaptureAllowed; });
    } else {
        return unexpectedExceptionCode(
                Status::EX_ILLEGAL_ARGUMENT,
                ("NPC::doesUidPermitPlaybackCapture: uid not found: " + std::to_string(uid))
                        .c_str());
    }
}

std::string NativePermissionController::dumpString() const {
    std::lock_guard l{m_};
    std::string res{"Permission map: \n"};
    for (size_t i = 0; i < permission_map_.size(); i++) {
        res += toString(static_cast<PermissionEnum>(i)) + ": ";
        bool is_first = true;
        for (uid_t uid : permission_map_[i]) {
            if (!is_first) {
                res += ", ";
            } else {
                is_first = false;
            }
            res += std::to_string(uid);
        }
        res += "\n";
    }
    return res;
}

}  // namespace com::android::media::permission
