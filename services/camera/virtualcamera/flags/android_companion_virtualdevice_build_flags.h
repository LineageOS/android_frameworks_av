/*
 * Copyright 2024 The Android Open Source Project
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

namespace android {
namespace companion {
namespace virtualdevice {
namespace flags {

// Returns true if the virtual camera service is enabled
// in the build.
//
// TODO(b/309090563) - Deprecate in favor of autogened library to query build
// flags once available.
bool virtual_camera_service_build_flag();

}  // namespace flags
}  // namespace virtualdevice
}  // namespace companion
}  // namespace android
