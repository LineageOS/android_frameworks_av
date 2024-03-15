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

#include <optional>

#include "android/hardware_buffer.h"
#include "util/Util.h"

namespace android {
namespace companion {
namespace virtualcamera {

// Jpeg-compress image into the output buffer.
// * width - width of the image, can be less than width of inBuffer.
// * heigh - height of the image, can be less than height of inBuffer.
// * quality - 0-100, higher number corresponds to higher quality.
// * inBuffer - Input buffer, the dimensions of the buffer must be aligned to
//   2*DCT_SIZE (16) to include necessary padding in case width and height of
//   image is not aligned with 2*DCT_SIZE.
// * app1ExifData - vector containing data to be included in APP1
//   segment. Can be empty.
// * outBufferSize - capacity of the output buffer.
// * outBuffer - output buffer to write compressed data into.
// Returns size of compressed data if the compression was successful,
// empty optional otherwise.
std::optional<size_t> compressJpeg(int width, int height, int quality,
                                   std::shared_ptr<AHardwareBuffer> inBuffer,
                                   const std::vector<uint8_t>& app1ExifData,
                                   size_t outBufferSize, void* outBuffer);

// Round the resolution to the closest higher resolution where width and height
// are divisible by 2*DCT_SIZE ().
Resolution roundTo2DctSize(Resolution resolution);

}  // namespace virtualcamera
}  // namespace companion
}  // namespace android

#endif  // ANDROID_COMPANION_VIRTUALCAMERA_JPEGUTIL_H
