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

#include <mutex>
#include <optional>
#include <unordered_map>

#include "IPermissionProvider.h"

#include <android-base/thread_annotations.h>
#include <com/android/media/permission/BnNativePermissionController.h>

namespace com::android::media::permission {

class NativePermissionController : public BnNativePermissionController, public IPermissionProvider {
    using Status = ::android::binder::Status;

  public:
    Status populatePackagesForUids(const std::vector<UidPackageState>& initialPackageStates) final;
    Status updatePackagesForUid(const UidPackageState& newPackageState) final;
    // end binder methods

    ::android::error::Result<std::vector<std::string>> getPackagesForUid(uid_t uid) const final;
    ::android::error::Result<bool> validateUidPackagePair(
            uid_t uid, const std::string& packageName) const final;

  private:
    mutable std::mutex m_;
    // map of app_ids to the set of packages names which could run in them (should be 1)
    std::unordered_map<uid_t, std::vector<std::string>> package_map_ GUARDED_BY(m_);
    bool is_package_populated_ GUARDED_BY(m_);
};
}  // namespace com::android::media::permission
