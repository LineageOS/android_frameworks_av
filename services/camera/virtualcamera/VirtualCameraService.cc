/*
 * Copyright 2023 The Android Open Source Project
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
#define LOG_TAG "VirtualCameraService"
#include "VirtualCameraService.h"

#include <algorithm>
#include <array>
#include <cinttypes>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <regex>
#include <variant>

#include "VirtualCameraDevice.h"
#include "VirtualCameraProvider.h"
#include "VirtualCameraTestInstance.h"
#include "aidl/android/companion/virtualcamera/Format.h"
#include "aidl/android/companion/virtualcamera/LensFacing.h"
#include "aidl/android/companion/virtualcamera/VirtualCameraConfiguration.h"
#include "android/binder_auto_utils.h"
#include "android/binder_interface_utils.h"
#include "android/binder_libbinder.h"
#include "android/binder_status.h"
#include "binder/Status.h"
#include "fmt/format.h"
#include "util/EglDisplayContext.h"
#include "util/EglUtil.h"
#include "util/Permissions.h"
#include "util/Util.h"

using ::android::binder::Status;

namespace android {
namespace companion {
namespace virtualcamera {

using ::aidl::android::companion::virtualcamera::Format;
using ::aidl::android::companion::virtualcamera::LensFacing;
using ::aidl::android::companion::virtualcamera::SensorOrientation;
using ::aidl::android::companion::virtualcamera::SupportedStreamConfiguration;
using ::aidl::android::companion::virtualcamera::VirtualCameraConfiguration;

// TODO(b/301023410) Make camera id range configurable / dynamic
// based on already registered devices.
std::atomic_int VirtualCameraService::sNextId{1000};

namespace {

constexpr int kVgaWidth = 640;
constexpr int kVgaHeight = 480;
constexpr int kMaxFps = 60;
constexpr int kTestCameraInputFps = 30;
constexpr char kEnableTestCameraCmd[] = "enable_test_camera";
constexpr char kDisableTestCameraCmd[] = "disable_test_camera";
constexpr char kHelp[] = "help";
constexpr char kShellCmdHelp[] = R"(
Usage:
   cmd virtual_camera command [--option=value]
Available commands:
 * enable_test_camera
     Options:
       --camera_id=(ID) - override numerical ID for test camera instance
       --lens_facing=(front|back|external) - specifies lens facing for test camera instance
 * disable_test_camera
)";
constexpr char kCreateVirtualDevicePermission[] =
    "android.permission.CREATE_VIRTUAL_DEVICE";

constexpr std::array<const char*, 3> kRequiredEglExtensions = {
    "GL_OES_EGL_image_external",
    "GL_OES_EGL_image_external_essl3",
    "GL_EXT_YUV_target",
};

ndk::ScopedAStatus validateConfiguration(
    const VirtualCameraConfiguration& configuration) {
  if (configuration.supportedStreamConfigs.empty()) {
    ALOGE("%s: No supported input configuration specified", __func__);
    return ndk::ScopedAStatus::fromServiceSpecificError(
        Status::EX_ILLEGAL_ARGUMENT);
  }

  if (configuration.virtualCameraCallback == nullptr) {
    ALOGE("%s: Input configuration is missing virtual camera callback",
          __func__);
    return ndk::ScopedAStatus::fromServiceSpecificError(
        Status::EX_ILLEGAL_ARGUMENT);
  }

  for (const SupportedStreamConfiguration& config :
       configuration.supportedStreamConfigs) {
    if (!isFormatSupportedForInput(config.width, config.height,
                                   config.pixelFormat, config.maxFps)) {
      ALOGE("%s: Requested unsupported input format: %d x %d (%d)", __func__,
            config.width, config.height, static_cast<int>(config.pixelFormat));
      return ndk::ScopedAStatus::fromServiceSpecificError(
          Status::EX_ILLEGAL_ARGUMENT);
    }
  }

  if (configuration.sensorOrientation != SensorOrientation::ORIENTATION_0 &&
      configuration.sensorOrientation != SensorOrientation::ORIENTATION_90 &&
      configuration.sensorOrientation != SensorOrientation::ORIENTATION_180 &&
      configuration.sensorOrientation != SensorOrientation::ORIENTATION_270) {
    return ndk::ScopedAStatus::fromServiceSpecificError(
        Status::EX_ILLEGAL_ARGUMENT);
  }

  if (configuration.lensFacing != LensFacing::FRONT &&
      configuration.lensFacing != LensFacing::BACK &&
      configuration.lensFacing != LensFacing::EXTERNAL) {
    return ndk::ScopedAStatus::fromServiceSpecificError(
        Status::EX_ILLEGAL_ARGUMENT);
  }

  return ndk::ScopedAStatus::ok();
}

enum class Command {
  ENABLE_TEST_CAMERA,
  DISABLE_TEST_CAMERA,
  HELP,
};

struct CommandWithOptions {
  Command command;
  std::map<std::string, std::string> optionToValueMap;
};

std::optional<int> parseInt(const std::string& s) {
  if (!std::all_of(s.begin(), s.end(), [](char c) { return std::isdigit(c); })) {
    return std::nullopt;
  }
  int ret = atoi(s.c_str());
  return ret > 0 ? std::optional(ret) : std::nullopt;
}

std::optional<LensFacing> parseLensFacing(const std::string& s) {
  static const std::map<std::string, LensFacing> strToLensFacing{
      {"front", LensFacing::FRONT},
      {"back", LensFacing::BACK},
      {"external", LensFacing::EXTERNAL}};
  auto it = strToLensFacing.find(s);
  return it == strToLensFacing.end() ? std::nullopt : std::optional(it->second);
}

std::variant<CommandWithOptions, std::string> parseCommand(
    const char** args, const uint32_t numArgs) {
  static const std::regex optionRegex("^--(\\w+)(?:=(.+))?$");
  static const std::map<std::string, Command> strToCommand{
      {kHelp, Command::HELP},
      {kEnableTestCameraCmd, Command::ENABLE_TEST_CAMERA},
      {kDisableTestCameraCmd, Command::DISABLE_TEST_CAMERA}};

  if (numArgs < 1) {
    return CommandWithOptions{.command = Command::HELP};
  }

  // We interpret the first argument as command;
  auto it = strToCommand.find(args[0]);
  if (it == strToCommand.end()) {
    return "Unknown command: " + std::string(args[0]);
  }

  CommandWithOptions cmd{.command = it->second};

  for (int i = 1; i < numArgs; i++) {
    std::cmatch cm;
    if (!std::regex_match(args[i], cm, optionRegex)) {
      return "Not an option: " + std::string(args[i]);
    }

    cmd.optionToValueMap[cm[1]] = cm[2];
  }

  return cmd;
};

ndk::ScopedAStatus verifyRequiredEglExtensions() {
  EglDisplayContext context;
  for (const char* eglExtension : kRequiredEglExtensions) {
    if (!isGlExtensionSupported(eglExtension)) {
      ALOGE("%s not supported", eglExtension);
      return ndk::ScopedAStatus::fromExceptionCodeWithMessage(
          EX_UNSUPPORTED_OPERATION,
          fmt::format(
              "Cannot create virtual camera, because required EGL extension {} "
              "is not supported on this system",
              eglExtension)
              .c_str());
    }
  }
  return ndk::ScopedAStatus::ok();
}

}  // namespace

VirtualCameraService::VirtualCameraService(
    std::shared_ptr<VirtualCameraProvider> virtualCameraProvider,
    const PermissionsProxy& permissionProxy)
    : mVirtualCameraProvider(virtualCameraProvider),
      mPermissionProxy(permissionProxy) {
}

ndk::ScopedAStatus VirtualCameraService::registerCamera(
    const ::ndk::SpAIBinder& token,
    const VirtualCameraConfiguration& configuration, const int32_t deviceId,
    bool* _aidl_return) {
  return registerCamera(token, configuration, sNextId++, deviceId, _aidl_return);
}

ndk::ScopedAStatus VirtualCameraService::registerCamera(
    const ::ndk::SpAIBinder& token,
    const VirtualCameraConfiguration& configuration, const int cameraId,
    const int32_t deviceId, bool* _aidl_return) {
  if (!mPermissionProxy.checkCallingPermission(kCreateVirtualDevicePermission)) {
    ALOGE("%s: caller (pid %d, uid %d) doesn't hold %s permission", __func__,
          getpid(), getuid(), kCreateVirtualDevicePermission);
    return ndk::ScopedAStatus::fromExceptionCode(EX_SECURITY);
  }

  if (_aidl_return == nullptr) {
    return ndk::ScopedAStatus::fromServiceSpecificError(
        Status::EX_ILLEGAL_ARGUMENT);
  }

  if (mVerifyEglExtensions) {
    auto status = verifyRequiredEglExtensions();
    if (!status.isOk()) {
      *_aidl_return = false;
      return status;
    }
  }

  auto status = validateConfiguration(configuration);
  if (!status.isOk()) {
    *_aidl_return = false;
    return status;
  }

  std::lock_guard lock(mLock);
  if (mTokenToCameraName.find(token) != mTokenToCameraName.end()) {
    ALOGE(
        "Attempt to register camera corresponding to already registered binder "
        "token: "
        "0x%" PRIxPTR,
        reinterpret_cast<uintptr_t>(token.get()));
    *_aidl_return = false;
    return ndk::ScopedAStatus::ok();
  }

  std::shared_ptr<VirtualCameraDevice> camera =
      mVirtualCameraProvider->createCamera(configuration, cameraId, deviceId);
  if (camera == nullptr) {
    ALOGE("Failed to create camera for binder token 0x%" PRIxPTR,
          reinterpret_cast<uintptr_t>(token.get()));
    *_aidl_return = false;
    return ndk::ScopedAStatus::fromServiceSpecificError(
        Status::EX_SERVICE_SPECIFIC);
  }

  mTokenToCameraName[token] = camera->getCameraName();
  *_aidl_return = true;
  return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus VirtualCameraService::unregisterCamera(
    const ::ndk::SpAIBinder& token) {
  if (!mPermissionProxy.checkCallingPermission(kCreateVirtualDevicePermission)) {
    ALOGE("%s: caller (pid %d, uid %d) doesn't hold %s permission", __func__,
          getpid(), getuid(), kCreateVirtualDevicePermission);
    return ndk::ScopedAStatus::fromExceptionCode(EX_SECURITY);
  }

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

  mTokenToCameraName.erase(it);
  return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus VirtualCameraService::getCameraId(
    const ::ndk::SpAIBinder& token, int32_t* _aidl_return) {
  if (!mPermissionProxy.checkCallingPermission(kCreateVirtualDevicePermission)) {
    ALOGE("%s: caller (pid %d, uid %d) doesn't hold %s permission", __func__,
          getpid(), getuid(), kCreateVirtualDevicePermission);
    return ndk::ScopedAStatus::fromExceptionCode(EX_SECURITY);
  }

  if (_aidl_return == nullptr) {
    return ndk::ScopedAStatus::fromServiceSpecificError(
        Status::EX_ILLEGAL_ARGUMENT);
  }

  auto camera = getCamera(token);
  if (camera == nullptr) {
    ALOGE(
        "Attempt to get camera id corresponding to unknown binder token: "
        "0x%" PRIxPTR,
        reinterpret_cast<uintptr_t>(token.get()));
    return ndk::ScopedAStatus::ok();
  }

  *_aidl_return = camera->getCameraId();

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

binder_status_t VirtualCameraService::handleShellCommand(int, int out, int err,
                                                         const char** args,
                                                         uint32_t numArgs) {
  if (numArgs <= 0) {
    dprintf(out, kShellCmdHelp);
    fsync(out);
    return STATUS_OK;
  }

  auto isNullptr = [](const char* ptr) { return ptr == nullptr; };
  if (args == nullptr || std::any_of(args, args + numArgs, isNullptr)) {
    return STATUS_BAD_VALUE;
  }

  std::variant<CommandWithOptions, std::string> cmdOrErrorMessage =
      parseCommand(args, numArgs);
  if (std::holds_alternative<std::string>(cmdOrErrorMessage)) {
    dprintf(err, "Error: %s\n",
            std::get<std::string>(cmdOrErrorMessage).c_str());
    return STATUS_BAD_VALUE;
  }

  const CommandWithOptions& cmd =
      std::get<CommandWithOptions>(cmdOrErrorMessage);
  binder_status_t status = STATUS_OK;
  switch (cmd.command) {
    case Command::HELP:
      dprintf(out, kShellCmdHelp);
      break;
    case Command::ENABLE_TEST_CAMERA:
      status = enableTestCameraCmd(out, err, cmd.optionToValueMap);
      break;
    case Command::DISABLE_TEST_CAMERA:
      disableTestCameraCmd(out);
      break;
  }

  fsync(err);
  fsync(out);
  return status;
}

binder_status_t VirtualCameraService::enableTestCameraCmd(
    const int out, const int err,
    const std::map<std::string, std::string>& options) {
  if (mTestCameraToken != nullptr) {
    dprintf(out, "Test camera is already enabled (%s).\n",
            getCamera(mTestCameraToken)->getCameraName().c_str());
    return STATUS_OK;
  }

  std::optional<int> cameraId;
  auto it = options.find("camera_id");
  if (it != options.end()) {
    cameraId = parseInt(it->second);
    if (!cameraId.has_value()) {
      dprintf(err, "Invalid camera_id: %s\n, must be number > 0",
              it->second.c_str());
      return STATUS_BAD_VALUE;
    }
  }

  std::optional<LensFacing> lensFacing;
  it = options.find("lens_facing");
  if (it != options.end()) {
    lensFacing = parseLensFacing(it->second);
    if (!lensFacing.has_value()) {
      dprintf(err, "Invalid lens_facing: %s\n, must be front|back|external",
              it->second.c_str());
      return STATUS_BAD_VALUE;
    }
  }

  sp<BBinder> token = sp<BBinder>::make();
  mTestCameraToken.set(AIBinder_fromPlatformBinder(token));

  bool ret;
  VirtualCameraConfiguration configuration;
  configuration.supportedStreamConfigs.push_back({.width = kVgaWidth,
                                                  .height = kVgaHeight,
                                                  Format::RGBA_8888,
                                                  .maxFps = kMaxFps});
  configuration.lensFacing = lensFacing.value_or(LensFacing::EXTERNAL);
  configuration.virtualCameraCallback =
      ndk::SharedRefBase::make<VirtualCameraTestInstance>(kTestCameraInputFps);
  registerCamera(mTestCameraToken, configuration, cameraId.value_or(sNextId++),
                 kDefaultDeviceId, &ret);
  if (ret) {
    dprintf(out, "Successfully registered test camera %s\n",
            getCamera(mTestCameraToken)->getCameraName().c_str());
  } else {
    dprintf(err, "Failed to create test camera\n");
  }
  return STATUS_OK;
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
