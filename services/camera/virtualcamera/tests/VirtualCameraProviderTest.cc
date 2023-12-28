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

#include <memory>

#include "VirtualCameraProvider.h"
#include "aidl/android/hardware/camera/common/CameraDeviceStatus.h"
#include "aidl/android/hardware/camera/common/Status.h"
#include "aidl/android/hardware/camera/common/TorchModeStatus.h"
#include "aidl/android/hardware/camera/provider/BnCameraProviderCallback.h"
#include "android/binder_auto_utils.h"
#include "android/binder_interface_utils.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "util/Util.h"

namespace android {
namespace companion {
namespace virtualcamera {
namespace {

using ::aidl::android::companion::virtualcamera::Format;
using ::aidl::android::companion::virtualcamera::LensFacing;
using ::aidl::android::companion::virtualcamera::SensorOrientation;
using ::aidl::android::companion::virtualcamera::SupportedStreamConfiguration;
using ::aidl::android::companion::virtualcamera::VirtualCameraConfiguration;
using ::aidl::android::hardware::camera::common::CameraDeviceStatus;
using ::aidl::android::hardware::camera::common::Status;
using ::aidl::android::hardware::camera::common::TorchModeStatus;
using ::aidl::android::hardware::camera::provider::BnCameraProviderCallback;
using ::testing::_;
using ::testing::ElementsAre;
using ::testing::Eq;
using ::testing::IsEmpty;
using ::testing::IsNull;
using ::testing::MatchesRegex;
using ::testing::Not;
using ::testing::Return;

constexpr int kVgaWidth = 640;
constexpr int kVgaHeight = 480;
constexpr int kMaxFps = 30;
constexpr char kVirtualCameraNameRegex[] =
    "device@[0-9]+\\.[0-9]+/virtual/[0-9]+";

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

class VirtualCameraProviderTest : public ::testing::Test {
 public:
  void SetUp() override {
    mCameraProvider = ndk::SharedRefBase::make<VirtualCameraProvider>();
    mMockCameraProviderCallback =
        ndk::SharedRefBase::make<MockCameraProviderCallback>();
    ON_CALL(*mMockCameraProviderCallback, cameraDeviceStatusChange)
        .WillByDefault([](const std::string&, CameraDeviceStatus) {
          return ndk::ScopedAStatus::ok();
        });
  }

 protected:
  std::shared_ptr<VirtualCameraProvider> mCameraProvider;
  std::shared_ptr<MockCameraProviderCallback> mMockCameraProviderCallback =
      ndk::SharedRefBase::make<MockCameraProviderCallback>();
  VirtualCameraConfiguration mInputConfig = VirtualCameraConfiguration{
      .supportedStreamConfigs = {SupportedStreamConfiguration{
          .width = kVgaWidth,
          .height = kVgaHeight,
          .pixelFormat = Format::YUV_420_888,
          .maxFps = kMaxFps}},
      .virtualCameraCallback = nullptr,
      .sensorOrientation = SensorOrientation::ORIENTATION_0,
      .lensFacing = LensFacing::FRONT};
};

TEST_F(VirtualCameraProviderTest, SetNullCameraCallbackFails) {
  // Attempting to set callback to nullptr should fail.
  EXPECT_FALSE(mCameraProvider->setCallback(nullptr).isOk());
}

TEST_F(VirtualCameraProviderTest, NoCamerasInitially) {
  std::vector<std::string> cameras;

  // Initially, the camera provider should return empty list
  // of cameras.
  ASSERT_TRUE(mCameraProvider->getCameraIdList(&cameras).isOk());
  EXPECT_THAT(cameras, IsEmpty());
}

TEST_F(VirtualCameraProviderTest, CreateCamera) {
  // When new camera is created, we expect
  // cameraDeviceStatusChange to be called exactly once with
  // PRESENT status.
  EXPECT_CALL(*mMockCameraProviderCallback,
              cameraDeviceStatusChange(_, CameraDeviceStatus::PRESENT))
      .WillOnce(Return(ndk::ScopedAStatus::ok()));

  ASSERT_TRUE(mCameraProvider->setCallback(mMockCameraProviderCallback).isOk());
  std::shared_ptr<VirtualCameraDevice> camera =
      mCameraProvider->createCamera(mInputConfig);
  EXPECT_THAT(camera, Not(IsNull()));
  EXPECT_THAT(camera->getCameraName(), MatchesRegex(kVirtualCameraNameRegex));

  // Created camera should be in the list of cameras.
  std::vector<std::string> cameraIds;
  ASSERT_TRUE(mCameraProvider->getCameraIdList(&cameraIds).isOk());
  EXPECT_THAT(cameraIds, ElementsAre(camera->getCameraName()));
}

TEST_F(VirtualCameraProviderTest, CreateCameraBeforeCallbackIsSet) {
  // We expect cameraDeviceStatusChange to be invoked even when the
  // setCallback configures the callback after camera is already created.
  EXPECT_CALL(*mMockCameraProviderCallback,
              cameraDeviceStatusChange(_, CameraDeviceStatus::PRESENT))
      .WillOnce(Return(ndk::ScopedAStatus::ok()));

  std::shared_ptr<VirtualCameraDevice> camera =
      mCameraProvider->createCamera(mInputConfig);
  ASSERT_TRUE(mCameraProvider->setCallback(mMockCameraProviderCallback).isOk());

  // Created camera should be in the list of cameras.
  std::vector<std::string> cameraIds;
  EXPECT_TRUE(mCameraProvider->getCameraIdList(&cameraIds).isOk());
  EXPECT_THAT(cameraIds, ElementsAre(camera->getCameraName()));
}

TEST_F(VirtualCameraProviderTest, RemoveCamera) {
  ASSERT_TRUE(mCameraProvider->setCallback(mMockCameraProviderCallback).isOk());
  std::shared_ptr<VirtualCameraDevice> camera =
      mCameraProvider->createCamera(mInputConfig);

  EXPECT_CALL(*mMockCameraProviderCallback,
              cameraDeviceStatusChange(Eq(camera->getCameraName()),
                                       CameraDeviceStatus::NOT_PRESENT))
      .WillOnce(Return(ndk::ScopedAStatus::ok()));
  EXPECT_TRUE(mCameraProvider->removeCamera(camera->getCameraName()));

  // There are no cameras present after only camera is removed.
  std::vector<std::string> cameraIds;
  ASSERT_TRUE(mCameraProvider->getCameraIdList(&cameraIds).isOk());
  EXPECT_THAT(cameraIds, IsEmpty());
}

TEST_F(VirtualCameraProviderTest, RemoveNonExistingCamera) {
  ASSERT_TRUE(mCameraProvider->setCallback(mMockCameraProviderCallback).isOk());
  std::shared_ptr<VirtualCameraDevice> camera =
      mCameraProvider->createCamera(mInputConfig);

  // Removing non-existing camera should fail.
  const std::string cameraName = "DefinitelyNoTCamera";
  EXPECT_FALSE(mCameraProvider->removeCamera(cameraName));

  // Camera should be still present in the camera list.
  std::vector<std::string> cameraIds;
  ASSERT_TRUE(mCameraProvider->getCameraIdList(&cameraIds).isOk());
  EXPECT_THAT(cameraIds, ElementsAre(camera->getCameraName()));
}

}  // namespace
}  // namespace virtualcamera
}  // namespace companion
}  // namespace android
