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

#define LOG_TAG "VirtualCamera"

#include <android/binder_stability.h>

#include <cstddef>

#include "VirtualCameraProvider.h"
#include "VirtualCameraService.h"
#include "android-base/logging.h"
#include "android/binder_manager.h"
#include "android/binder_process.h"
#include "log/log.h"

using ::android::companion::virtualcamera::VirtualCameraProvider;
using ::android::companion::virtualcamera::VirtualCameraService;

namespace {
// Default recommended RPC thread count for camera provider implementations
const int HWBINDER_THREAD_COUNT = 6;

constexpr char kVirtualCameraServiceName[] = "virtual_camera";
}  // namespace

int main() {
  ALOGI("virtual_camera service is starting.");

  ABinderProcess_setThreadPoolMaxThreadCount(HWBINDER_THREAD_COUNT);

  std::shared_ptr<VirtualCameraProvider> defaultProvider =
      ndk::SharedRefBase::make<VirtualCameraProvider>();
  const std::string serviceName =
      std::string(VirtualCameraProvider::descriptor) + "/virtual/0";

  auto aidlBinder = defaultProvider->asBinder();
  AIBinder_forceDowngradeToLocalStability(aidlBinder.get());
  binder_exception_t ret = AServiceManager_registerLazyService(
      aidlBinder.get(), serviceName.c_str());
  LOG_ALWAYS_FATAL_IF(
      ret != EX_NONE,
      "Error while registering virtual camera provider service: %d", ret);

  std::shared_ptr<VirtualCameraService> virtualCameraService =
      ndk::SharedRefBase::make<VirtualCameraService>(defaultProvider);
  ret = AServiceManager_registerLazyService(
      virtualCameraService->asBinder().get(), kVirtualCameraServiceName);
  LOG_ALWAYS_FATAL_IF(ret != EX_NONE,
                      "Error while registering virtual camera service: %d", ret);

  ABinderProcess_joinThreadPool();
  return EXIT_FAILURE;  // should not reach
}
