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

#ifndef ANDROID_COMPANION_VIRTUALCAMERA_PERMISSIONS_H
#define ANDROID_COMPANION_VIRTUALCAMERA_PERMISSIONS_H

#include <string>

#include "sys/types.h"

namespace android {
namespace companion {
namespace virtualcamera {

class PermissionsProxy {
 public:
  virtual ~PermissionsProxy() = default;

  // Checks whether caller holds permission. Do not use with runtime permissions
  // as the default implementation uses PermissionCache which doesn't reflect
  // possible runtime changes of permissions.
  //
  // Returns true in case caller holds the permission, false otherwise or if
  // there was any error while verifying the permission.
  virtual bool checkCallingPermission(const std::string& permission) const = 0;

  // Get instance of PermissionProxy.
  static const PermissionsProxy& get();
};

}  // namespace virtualcamera
}  // namespace companion
}  // namespace android

#endif  // ANDROID_COMPANION_VIRTUALCAMERA_PERMISSIONS_H
