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

#ifndef ANDROID_COMPANION_VIRTUALCAMERA_EGLUTIL_H
#define ANDROID_COMPANION_VIRTUALCAMERA_EGLUTIL_H

namespace android {
namespace companion {
namespace virtualcamera {

// Returns true if the EGL is in an error state and logs the error.
bool checkEglError(const char* operation = "EGL operation");

// Returns true if the GL extension is supported, false otherwise.
bool isGlExtensionSupported(const char* extension);

int getMaximumTextureSize();

}  // namespace virtualcamera
}  // namespace companion
}  // namespace android

#endif  // ANDROID_COMPANION_VIRTUALCAMERA_EGLUTIL_H
