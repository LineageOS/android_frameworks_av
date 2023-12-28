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

#include <cstdio>
#include <memory>

#include "VirtualCameraService.h"
#include "aidl/android/companion/virtualcamera/BnVirtualCameraCallback.h"
#include "aidl/android/companion/virtualcamera/VirtualCameraConfiguration.h"
#include "aidl/android/hardware/camera/provider/BnCameraProviderCallback.h"
#include "aidl/android/hardware/graphics/common/PixelFormat.h"
#include "android/binder_auto_utils.h"
#include "android/binder_interface_utils.h"
#include "android/binder_libbinder.h"
#include "android/binder_status.h"
#include "binder/Binder.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "util/Permissions.h"
#include "utils/Errors.h"

namespace android {
namespace companion {
namespace virtualcamera {
namespace {

using ::aidl::android::companion::virtualcamera::BnVirtualCameraCallback;
using ::aidl::android::companion::virtualcamera::Format;
using ::aidl::android::companion::virtualcamera::LensFacing;
using ::aidl::android::companion::virtualcamera::SensorOrientation;
using ::aidl::android::companion::virtualcamera::VirtualCameraConfiguration;
using ::aidl::android::hardware::camera::common::CameraDeviceStatus;
using ::aidl::android::hardware::camera::common::TorchModeStatus;
using ::aidl::android::hardware::camera::provider::BnCameraProviderCallback;
using ::aidl::android::hardware::graphics::common::PixelFormat;
using ::aidl::android::view::Surface;
using ::testing::_;
using ::testing::Eq;
using ::testing::Ge;
using ::testing::IsEmpty;
using ::testing::IsNull;
using ::testing::Not;
using ::testing::Return;
using ::testing::SizeIs;

constexpr int kVgaWidth = 640;
constexpr int kVgaHeight = 480;
constexpr int kMaxFps = 30;
constexpr SensorOrientation kSensorOrientation =
    SensorOrientation::ORIENTATION_0;
constexpr LensFacing kLensFacing = LensFacing::FRONT;
constexpr char kCreateVirtualDevicePermissions[] =
    "android.permission.CREATE_VIRTUAL_DEVICE";

const VirtualCameraConfiguration kEmptyVirtualCameraConfiguration;

VirtualCameraConfiguration createConfiguration(const int width, const int height,
                                               const Format format,
                                               const int maxFps) {
  VirtualCameraConfiguration configuration;
  configuration.supportedStreamConfigs.push_back({.width = width,
                                                  .height = height,
                                                  .pixelFormat = format,
                                                  .maxFps = maxFps});
  configuration.sensorOrientation = kSensorOrientation;
  configuration.lensFacing = kLensFacing;
  return configuration;
}

class MockCameraProviderCallback : public BnCameraProviderCallback {
 public:
  MOCK_METHOD(ndk::ScopedAStatus, cameraDeviceStatusChange,
              (const std::string&, CameraDeviceStatus), (override));
  MOCK_METHOD(ndk::ScopedAStatus, torchModeStatusChange,
              (const std::string&, TorchModeStatus), (override));
  MOCK_METHOD(ndk::ScopedAStatus, physicalCameraDeviceStatusChange,
              (const std::string&, const std::string&, CameraDeviceStatus),
              (override));
};

class MockPermissionsProxy : public PermissionsProxy {
 public:
  MOCK_METHOD(bool, checkCallingPermission, (const std::string&),
              (const override));
};

class VirtualCameraServiceTest : public ::testing::Test {
 public:
  void SetUp() override {
    mCameraProvider = ndk::SharedRefBase::make<VirtualCameraProvider>();
    mMockCameraProviderCallback =
        ndk::SharedRefBase::make<MockCameraProviderCallback>();
    ON_CALL(*mMockCameraProviderCallback, cameraDeviceStatusChange)
        .WillByDefault([](const std::string&, CameraDeviceStatus) {
          return ndk::ScopedAStatus::ok();
        });
    mCameraProvider->setCallback(mMockCameraProviderCallback);
    mCameraService = ndk::SharedRefBase::make<VirtualCameraService>(
        mCameraProvider, mMockPermissionsProxy);

    ON_CALL(mMockPermissionsProxy, checkCallingPermission)
        .WillByDefault(Return(true));

    mDevNullFd = open("/dev/null", O_RDWR);
    ASSERT_THAT(mDevNullFd, Ge(0));
  }

  void createCamera() {
    mOwnerToken = sp<BBinder>::make();
    mNdkOwnerToken.set(AIBinder_fromPlatformBinder(mOwnerToken));
    bool aidlRet;

    ASSERT_TRUE(mCameraService
                    ->registerCamera(mNdkOwnerToken,
                                     mVgaYUV420OnlyConfiguration, &aidlRet)
                    .isOk());
    ASSERT_TRUE(aidlRet);
  }

  void TearDown() override {
    close(mDevNullFd);
  }

  void execute_shell_command(const std::string cmd) {
    std::array<const char*, 1> args{cmd.data()};
    ASSERT_THAT(
        mCameraService->handleShellCommand(mDevNullFd, mDevNullFd, mDevNullFd,
                                           args.data(), args.size()),
        Eq(NO_ERROR));
  }

  std::vector<std::string> getCameraIds() {
    std::vector<std::string> cameraIds;
    EXPECT_TRUE(mCameraProvider->getCameraIdList(&cameraIds).isOk());
    return cameraIds;
  }

 protected:
  std::shared_ptr<VirtualCameraService> mCameraService;
  std::shared_ptr<VirtualCameraProvider> mCameraProvider;
  std::shared_ptr<MockCameraProviderCallback> mMockCameraProviderCallback =
      ndk::SharedRefBase::make<MockCameraProviderCallback>();
  MockPermissionsProxy mMockPermissionsProxy;

  sp<BBinder> mOwnerToken;
  ndk::SpAIBinder mNdkOwnerToken;

  int mDevNullFd;

  VirtualCameraConfiguration mVgaYUV420OnlyConfiguration =
      createConfiguration(kVgaWidth, kVgaHeight, Format::YUV_420_888, kMaxFps);
};

TEST_F(VirtualCameraServiceTest, RegisterCameraWithYuvInputSucceeds) {
  sp<BBinder> token = sp<BBinder>::make();
  ndk::SpAIBinder ndkToken(AIBinder_fromPlatformBinder(token));
  bool aidlRet;

  ASSERT_TRUE(
      mCameraService
          ->registerCamera(ndkToken, mVgaYUV420OnlyConfiguration, &aidlRet)
          .isOk());

  EXPECT_TRUE(aidlRet);
  EXPECT_THAT(getCameraIds(), SizeIs(1));
}

TEST_F(VirtualCameraServiceTest, RegisterCameraWithRgbaInputSucceeds) {
  sp<BBinder> token = sp<BBinder>::make();
  ndk::SpAIBinder ndkToken(AIBinder_fromPlatformBinder(token));
  bool aidlRet;

  VirtualCameraConfiguration config =
      createConfiguration(kVgaWidth, kVgaHeight, Format::RGBA_8888, kMaxFps);

  ASSERT_TRUE(mCameraService->registerCamera(ndkToken, config, &aidlRet).isOk());

  EXPECT_TRUE(aidlRet);
  EXPECT_THAT(getCameraIds(), SizeIs(1));
}

TEST_F(VirtualCameraServiceTest, RegisterCameraTwiceSecondReturnsFalse) {
  createCamera();
  bool aidlRet;

  ASSERT_TRUE(mCameraService
                  ->registerCamera(mNdkOwnerToken, mVgaYUV420OnlyConfiguration,
                                   &aidlRet)
                  .isOk());
  EXPECT_FALSE(aidlRet);
  EXPECT_THAT(getCameraIds(), SizeIs(1));
}

TEST_F(VirtualCameraServiceTest, EmptyConfigurationFails) {
  bool aidlRet;

  ASSERT_FALSE(mCameraService
                   ->registerCamera(mNdkOwnerToken,
                                    kEmptyVirtualCameraConfiguration, &aidlRet)
                   .isOk());
  EXPECT_FALSE(aidlRet);
  EXPECT_THAT(getCameraIds(), IsEmpty());
}

TEST_F(VirtualCameraServiceTest, ConfigurationWithUnsupportedPixelFormatFails) {
  bool aidlRet;

  VirtualCameraConfiguration config =
      createConfiguration(kVgaWidth, kVgaHeight, Format::UNKNOWN, kMaxFps);

  ASSERT_FALSE(
      mCameraService->registerCamera(mNdkOwnerToken, config, &aidlRet).isOk());
  EXPECT_FALSE(aidlRet);
  EXPECT_THAT(getCameraIds(), IsEmpty());
}

TEST_F(VirtualCameraServiceTest, ConfigurationWithTooHighResFails) {
  bool aidlRet;
  VirtualCameraConfiguration config =
      createConfiguration(1000000, 1000000, Format::YUV_420_888, kMaxFps);

  ASSERT_FALSE(
      mCameraService->registerCamera(mNdkOwnerToken, config, &aidlRet).isOk());
  EXPECT_FALSE(aidlRet);
  EXPECT_THAT(getCameraIds(), IsEmpty());
}

TEST_F(VirtualCameraServiceTest, ConfigurationWithUnalignedResolutionFails) {
  bool aidlRet;
  VirtualCameraConfiguration config =
      createConfiguration(641, 481, Format::YUV_420_888, kMaxFps);

  ASSERT_FALSE(
      mCameraService->registerCamera(mNdkOwnerToken, config, &aidlRet).isOk());
  EXPECT_FALSE(aidlRet);
  EXPECT_THAT(getCameraIds(), IsEmpty());
}

TEST_F(VirtualCameraServiceTest, ConfigurationWithNegativeResolutionFails) {
  bool aidlRet;
  VirtualCameraConfiguration config =
      createConfiguration(-1, kVgaHeight, Format::YUV_420_888, kMaxFps);

  ASSERT_FALSE(
      mCameraService->registerCamera(mNdkOwnerToken, config, &aidlRet).isOk());
  EXPECT_FALSE(aidlRet);
  EXPECT_THAT(getCameraIds(), IsEmpty());
}

TEST_F(VirtualCameraServiceTest, ConfigurationWithTooLowMaxFpsFails) {
  bool aidlRet;
  VirtualCameraConfiguration config =
      createConfiguration(kVgaWidth, kVgaHeight, Format::YUV_420_888, 0);

  ASSERT_FALSE(
      mCameraService->registerCamera(mNdkOwnerToken, config, &aidlRet).isOk());
  EXPECT_FALSE(aidlRet);
  EXPECT_THAT(getCameraIds(), IsEmpty());
}

TEST_F(VirtualCameraServiceTest, ConfigurationWithTooHighMaxFpsFails) {
  bool aidlRet;
  VirtualCameraConfiguration config =
      createConfiguration(kVgaWidth, kVgaHeight, Format::YUV_420_888, 90);

  ASSERT_FALSE(
      mCameraService->registerCamera(mNdkOwnerToken, config, &aidlRet).isOk());
  EXPECT_FALSE(aidlRet);
  EXPECT_THAT(getCameraIds(), IsEmpty());
}

TEST_F(VirtualCameraServiceTest, GetCamera) {
  createCamera();

  EXPECT_THAT(mCameraService->getCamera(mNdkOwnerToken), Not(IsNull()));

  sp<BBinder> otherToken = sp<BBinder>::make();
  EXPECT_THAT(mCameraService->getCamera(
                  ndk::SpAIBinder(AIBinder_fromPlatformBinder(otherToken))),
              IsNull());
}

TEST_F(VirtualCameraServiceTest, UnregisterCamera) {
  createCamera();

  EXPECT_THAT(mCameraService->getCamera(mNdkOwnerToken), Not(IsNull()));

  mCameraService->unregisterCamera(mNdkOwnerToken);

  EXPECT_THAT(mCameraService->getCamera(mNdkOwnerToken), IsNull());
}

TEST_F(VirtualCameraServiceTest, RegisterCameraWithoutPermissionFails) {
  bool aidlRet;
  EXPECT_CALL(mMockPermissionsProxy,
              checkCallingPermission(kCreateVirtualDevicePermissions))
      .WillOnce(Return(false));

  EXPECT_THAT(mCameraService
                  ->registerCamera(mNdkOwnerToken, mVgaYUV420OnlyConfiguration,
                                   &aidlRet)
                  .getExceptionCode(),
              Eq(EX_SECURITY));
}

TEST_F(VirtualCameraServiceTest, UnregisterCameraWithoutPermissionFails) {
  EXPECT_CALL(mMockPermissionsProxy,
              checkCallingPermission(kCreateVirtualDevicePermissions))
      .WillOnce(Return(false));

  EXPECT_THAT(
      mCameraService->unregisterCamera(mNdkOwnerToken).getExceptionCode(),
      Eq(EX_SECURITY));
}

TEST_F(VirtualCameraServiceTest, GetIdWithoutPermissionFails) {
  int32_t aidlRet;
  EXPECT_CALL(mMockPermissionsProxy,
              checkCallingPermission(kCreateVirtualDevicePermissions))
      .WillOnce(Return(false));

  EXPECT_THAT(
      mCameraService->getCameraId(mNdkOwnerToken, &aidlRet).getExceptionCode(),
      Eq(EX_SECURITY));
}

TEST_F(VirtualCameraServiceTest, UnregisterCameraWithUnknownToken) {
  createCamera();

  EXPECT_THAT(mCameraService->getCamera(mNdkOwnerToken), Not(IsNull()));

  auto otherToken = sp<BBinder>::make();
  ndk::SpAIBinder ndkOtherToken(AIBinder_fromPlatformBinder(otherToken));
  mCameraService->unregisterCamera(ndkOtherToken);

  EXPECT_THAT(mCameraService->getCamera(mNdkOwnerToken), Not(IsNull()));
}

TEST_F(VirtualCameraServiceTest, ShellCmdWithNullArgs) {
  EXPECT_EQ(mCameraService->handleShellCommand(
                /*in=*/mDevNullFd, /*out=*/mDevNullFd, /*err=*/mDevNullFd,
                /*args=*/nullptr, /*numArgs=*/1),
            STATUS_BAD_VALUE);

  std::array<const char*, 1> args{nullptr};
  EXPECT_EQ(mCameraService->handleShellCommand(
                /*in=*/mDevNullFd, /*out=*/mDevNullFd, /*err=*/mDevNullFd,
                args.data(), /*numArgs=*/1),
            STATUS_BAD_VALUE);
}

TEST_F(VirtualCameraServiceTest, ShellCmdWithNoArgs) {
  EXPECT_EQ(mCameraService->handleShellCommand(
                /*in=*/mDevNullFd, /*out=*/mDevNullFd, /*err=*/mDevNullFd,
                /*args=*/nullptr, /*numArgs=*/0),
            STATUS_OK);
}

TEST_F(VirtualCameraServiceTest, TestCameraShellCmd) {
  execute_shell_command("enable_test_camera");

  std::vector<std::string> cameraIdsAfterEnable = getCameraIds();
  EXPECT_THAT(cameraIdsAfterEnable, SizeIs(1));

  execute_shell_command("disable_test_camera");

  std::vector<std::string> cameraIdsAfterDisable = getCameraIds();
  EXPECT_THAT(cameraIdsAfterDisable, IsEmpty());
}

}  // namespace
}  // namespace virtualcamera
}  // namespace companion
}  // namespace android
