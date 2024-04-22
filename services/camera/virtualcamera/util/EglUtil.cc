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
#define LOG_TAG "EglUtil"
#include "EglUtil.h"

#include <cstring>

#include "EglDisplayContext.h"
#include "GLES/gl.h"
#include "log/log.h"

namespace android {
namespace companion {
namespace virtualcamera {

// Lower bound for maximum supported texture size is at least 2048x2048
constexpr int kDefaultMaxTextureSize = 2048;

bool checkEglError(const char* operation) {
  GLenum err = glGetError();
  if (err == GL_NO_ERROR) {
    return false;
  }
  ALOGE("%s failed: %d", operation, err);
  return true;
}

bool isGlExtensionSupported(const char* extension) {
  const char* extensions =
      reinterpret_cast<const char*>(glGetString(GL_EXTENSIONS));
  if (extension == nullptr || extensions == nullptr) {
    return false;
  }
  return strstr(extensions, extension) != nullptr;
}

int getMaximumTextureSize() {
  static const int kMaxTextureSize = [] {
    EglDisplayContext displayContext;
    displayContext.makeCurrent();
    int maxTextureSize = -1;
    glGetIntegerv(GL_MAX_TEXTURE_SIZE, &maxTextureSize);
    return maxTextureSize;
  }();
  if (kMaxTextureSize <= 0) {
    return kDefaultMaxTextureSize;
  }
  return kMaxTextureSize;
}

}  // namespace virtualcamera
}  // namespace companion
}  // namespace android
