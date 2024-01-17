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

#include "Util.h"

#include <unistd.h>

#include <algorithm>
#include <array>

#include "jpeglib.h"

namespace android {
namespace companion {
namespace virtualcamera {

using ::aidl::android::companion::virtualcamera::Format;
using ::aidl::android::hardware::common::NativeHandle;

// Lower bound for maximal supported texture size is at least 2048x2048
// but on most platforms will be more.
// TODO(b/301023410) - Query actual max texture size.
constexpr int kMaxTextureSize = 2048;
constexpr int kLibJpegDctSize = DCTSIZE;
constexpr int kMaxFpsUpperLimit = 60;

constexpr std::array<Format, 2> kSupportedFormats{Format::YUV_420_888,
                                                  Format::RGBA_8888};

sp<Fence> importFence(const NativeHandle& aidlHandle) {
  if (aidlHandle.fds.size() != 1) {
    return sp<Fence>::make();
  }

  return sp<Fence>::make(::dup(aidlHandle.fds[0].get()));
}

bool isPixelFormatSupportedForInput(const Format format) {
  return std::find(kSupportedFormats.begin(), kSupportedFormats.end(),
                   format) != kSupportedFormats.end();
}

// Returns true if specified format is supported for virtual camera input.
bool isFormatSupportedForInput(const int width, const int height,
                               const Format format, const int maxFps) {
  if (!isPixelFormatSupportedForInput(format)) {
    return false;
  }

  if (width <= 0 || height <= 0 || width > kMaxTextureSize ||
      height > kMaxTextureSize) {
    return false;
  }

  if (width % kLibJpegDctSize != 0 || height % kLibJpegDctSize != 0) {
    // Input dimension needs to be multiple of libjpeg DCT size.
    // TODO(b/301023410) This restriction can be removed once we add support for
    // unaligned jpeg compression.
    return false;
  }

  if (maxFps <= 0 || maxFps > kMaxFpsUpperLimit) {
    return false;
  }

  return true;
}

}  // namespace virtualcamera
}  // namespace companion
}  // namespace android
