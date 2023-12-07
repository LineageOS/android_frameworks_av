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

// #define LOG_NDEBUG 0
#define LOG_TAG "VirtualCameraPermissions"

#include "Permissions.h"

#include "binder/PermissionCache.h"
#include "log/log.h"

namespace android {
namespace companion {
namespace virtualcamera {
namespace {

class PermissionsProxyImpl : public PermissionsProxy {
 public:
  bool checkCallingPermission(const std::string& permission) const override;
};

bool PermissionsProxyImpl::checkCallingPermission(
    const std::string& permission) const {
  int32_t uid;
  int32_t pid;
  const bool hasPermission = PermissionCache::checkCallingPermission(
      String16(permission.c_str()), &pid, &uid);

  ALOGV("%s: Checking %s permission for pid %d uid %d: %s", __func__,
        permission.c_str(), pid, uid, hasPermission ? "granted" : "denied");
  return hasPermission;
}
}  // namespace

const PermissionsProxy& PermissionsProxy::get() {
  static PermissionsProxyImpl sPermissionProxyImpl;
  return sPermissionProxyImpl;
}

}  // namespace virtualcamera
}  // namespace companion
}  // namespace android
