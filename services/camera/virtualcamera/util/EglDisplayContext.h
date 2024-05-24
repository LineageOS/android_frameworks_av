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

#ifndef ANDROID_COMPANION_VIRTUALCAMERA_EGLDISPLAYCONTEXT_H
#define ANDROID_COMPANION_VIRTUALCAMERA_EGLDISPLAYCONTEXT_H

#include <memory>

#include "EGL/egl.h"
#include "system/window.h"

namespace android {
namespace companion {
namespace virtualcamera {

// Encapsulated EGLDisplay & EGLContext.
//
// Upon construction, this object will create and configure new
// EGLDisplay & EGLContext and will destroy them once it goes
// out of scope.
class EglDisplayContext {
 public:
  EglDisplayContext(std::shared_ptr<ANativeWindow> nativeWindow = nullptr);
  ~EglDisplayContext();

  // Sets EGLDisplay & EGLContext for current thread.
  //
  // Returns true on success, false otherwise.
  bool makeCurrent();

  EGLDisplay getEglDisplay() const;

  // Returns true if this instance encapsulates successfully initialized
  // EGLDisplay & EGLContext.
  bool isInitialized() const;

  void swapBuffers() const;

 private:
  std::shared_ptr<ANativeWindow> mNativeWindow;

  EGLDisplay mEglDisplay;
  EGLSurface mEglSurface;
  EGLContext mEglContext;
  EGLConfig mEglConfig;
};

}  // namespace virtualcamera
}  // namespace companion
}  // namespace android

#endif  // ANDROID_COMPANION_VIRTUALCAMERA_EGLDISPLAYCONTEXT_H
