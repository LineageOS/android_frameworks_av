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
#include "android/binder_status.h"
#define LOG_TAG "VirtualCameraService"
#include "VirtualCameraService.h"

#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <mutex>

#include "VirtualCameraDevice.h"
#include "VirtualCameraProvider.h"
#include "android/binder_auto_utils.h"
#include "android/binder_libbinder.h"
#include "binder/Status.h"

using ::android::binder::Status;

namespace android {
namespace companion {
namespace virtualcamera {

using ::aidl::android::companion::virtualcamera::VirtualCameraConfiguration;

namespace {

constexpr char kEnableTestCameraCmd[] = "enable_test_camera";
constexpr char kDisableTestCameraCmd[] = "disable_test_camera";
constexpr char kShellCmdHelp[] = R"(
Available commands:
 * enable_test_camera
 * disable_test_camera
)";

}  // namespace

VirtualCameraService::VirtualCameraService(
    std::shared_ptr<VirtualCameraProvider> virtualCameraProvider)
    : mVirtualCameraProvider(virtualCameraProvider) {
}

ndk::ScopedAStatus VirtualCameraService::registerCamera(
    const ::ndk::SpAIBinder& token,
    const VirtualCameraConfiguration& configuration, bool* _aidl_return) {
  (void)configuration;
  if (_aidl_return == nullptr) {
    return ndk::ScopedAStatus::fromServiceSpecificError(
        Status::EX_ILLEGAL_ARGUMENT);
  }
  *_aidl_return = true;

  std::lock_guard lock(mLock);
  if (mTokenToCameraName.find(token) != mTokenToCameraName.end()) {
    ALOGE(
        "Attempt to register camera corresponding to already registered binder "
        "token: "
        "0x%" PRIxPTR,
        reinterpret_cast<uintptr_t>(token.get()));
    *_aidl_return = false;
  }

  // TODO(b/301023410) Validate configuration and pass it to the camera.
  std::shared_ptr<VirtualCameraDevice> camera =
      mVirtualCameraProvider->createCamera(configuration.virtualCameraCallback);
  if (camera == nullptr) {
    ALOGE("Failed to create camera for binder token 0x%" PRIxPTR,
          reinterpret_cast<uintptr_t>(token.get()));
    *_aidl_return = false;
    return ndk::ScopedAStatus::fromServiceSpecificError(
        Status::EX_SERVICE_SPECIFIC);
  }

  mTokenToCameraName[token] = camera->getCameraName();
  return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus VirtualCameraService::unregisterCamera(
    const ::ndk::SpAIBinder& token) {
  std::lock_guard lock(mLock);

  auto it = mTokenToCameraName.find(token);
  if (it == mTokenToCameraName.end()) {
    ALOGE(
        "Attempt to unregister camera corresponding to unknown binder token: "
        "0x%" PRIxPTR,
        reinterpret_cast<uintptr_t>(token.get()));
    return ndk::ScopedAStatus::ok();
  }

  mVirtualCameraProvider->removeCamera(it->second);

  return ndk::ScopedAStatus::ok();
}

std::shared_ptr<VirtualCameraDevice> VirtualCameraService::getCamera(
    const ::ndk::SpAIBinder& token) {
  if (token == nullptr) {
    return nullptr;
  }

  std::lock_guard lock(mLock);
  auto it = mTokenToCameraName.find(token);
  if (it == mTokenToCameraName.end()) {
    return nullptr;
  }

  return mVirtualCameraProvider->getCamera(it->second);
}

binder_status_t VirtualCameraService::handleShellCommand(int in, int out,
                                                         int err,
                                                         const char** args,
                                                         uint32_t numArgs) {
  if (numArgs <= 0) {
    dprintf(out, kShellCmdHelp);
  }

  if (args == nullptr || args[0] == nullptr) {
    return STATUS_BAD_VALUE;
  }
  const char* const cmd = args[0];
  if (strcmp(kEnableTestCameraCmd, cmd) == 0) {
    enableTestCameraCmd(in, err);
  } else if (strcmp(kDisableTestCameraCmd, cmd) == 0) {
    disableTestCameraCmd(in);
  } else {
    dprintf(out, kShellCmdHelp);
  }

  fsync(out);
  return STATUS_OK;
}

void VirtualCameraService::enableTestCameraCmd(const int out, const int err) {
  if (mTestCameraToken != nullptr) {
    dprintf(out, "Test camera is already enabled (%s).",
            getCamera(mTestCameraToken)->getCameraName().c_str());
    return;
  }

  sp<BBinder> token = sp<BBinder>::make();
  mTestCameraToken.set(AIBinder_fromPlatformBinder(token));

  bool ret;
  registerCamera(mTestCameraToken, VirtualCameraConfiguration(), &ret);
  if (ret) {
    dprintf(out, "Successfully registered test camera %s",
            getCamera(mTestCameraToken)->getCameraName().c_str());
  } else {
    dprintf(err, "Failed to create test camera");
  }
}

void VirtualCameraService::disableTestCameraCmd(const int out) {
  if (mTestCameraToken == nullptr) {
    dprintf(out, "Test camera is not registered.");
  }
  unregisterCamera(mTestCameraToken);
  mTestCameraToken.set(nullptr);
}

}  // namespace virtualcamera
}  // namespace companion
}  // namespace android
