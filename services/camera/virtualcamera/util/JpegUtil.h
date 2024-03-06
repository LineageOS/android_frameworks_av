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

#ifndef ANDROID_COMPANION_VIRTUALCAMERA_JPEGUTIL_H
#define ANDROID_COMPANION_VIRTUALCAMERA_JPEGUTIL_H

#include <memory>

#include "android/hardware_buffer.h"
#include "system/graphics.h"

namespace android {
namespace companion {
namespace virtualcamera {

// Jpeg-compress image into the output buffer.
// Returns true if the compression was successful, false otherwise.
bool compressJpeg(int width, int height, const android_ycbcr& ycbcr,
                  size_t outBufferSize, void* outBuffer);

// Jpeg-compress all-black image into the output buffer.
// Returns true if the compression was successful, false otherwise.
bool compressBlackJpeg(int width, int height, size_t outBufferSize,
                       void* outBuffer);

}  // namespace virtualcamera
}  // namespace companion
}  // namespace android

#endif  // ANDROID_COMPANION_VIRTUALCAMERA_JPEGUTIL_H
