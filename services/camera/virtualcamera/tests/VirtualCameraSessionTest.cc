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

#include <aidl/android/hardware/graphics/common/Dataspace.h>
#include <android_companion_virtualdevice_flags.h>
#include <flag_macros.h>

#include <cstdint>
#include <memory>

#include "VirtualCameraDevice.h"
#include "VirtualCameraSession.h"
#include "aidl/android/companion/virtualcamera/BnVirtualCameraCallback.h"
#include "aidl/android/companion/virtualcamera/SupportedStreamConfiguration.h"
#include "aidl/android/companion/virtualcamera/VirtualCameraConfiguration.h"
#include "aidl/android/companion/virtualcamera/VirtualCameraMetadata.h"
#include "aidl/android/hardware/camera/common/Status.h"
#include "aidl/android/hardware/camera/device/BnCameraDeviceCallback.h"
#include "aidl/android/hardware/camera/device/StreamConfiguration.h"
#include "aidl/android/hardware/graphics/common/PixelFormat.h"
#include "android/binder_auto_utils.h"
#include "android/binder_interface_utils.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "util/AidlUtil.h"
#include "util/MetadataUtil.h"

namespace android {
namespace companion {
namespace virtualcamera {
namespace {

constexpr char kCameraId[] = "42";
constexpr int kQvgaWidth = 320;
constexpr int kQvgaHeight = 240;
constexpr int kVgaWidth = 640;
constexpr int kVgaHeight = 480;
constexpr int kSvgaWidth = 800;
constexpr int kSvgaHeight = 600;
constexpr int kMaxFps = 30;
constexpr int kStreamId = 0;
constexpr int kSecondStreamId = 1;
constexpr int kDefaultDeviceId = 0;
constexpr int kDeviceId = 5;
constexpr FpsRange kFpsRange = FpsRange(5, 10);
constexpr float kFocalLength = 2.1f;

using ::aidl::android::companion::virtualcamera::BnVirtualCameraCallback;
using ::aidl::android::companion::virtualcamera::Format;
using ::aidl::android::companion::virtualcamera::ICaptureResultConsumer;
using ::aidl::android::companion::virtualcamera::LensFacing;
using ::aidl::android::companion::virtualcamera::SensorOrientation;
using ::aidl::android::companion::virtualcamera::SupportedStreamConfiguration;
using ::aidl::android::companion::virtualcamera::VirtualCameraConfiguration;
using ::aidl::android::companion::virtualcamera::VirtualCameraMetadata;
using ::aidl::android::hardware::camera::common::Status;
using ::aidl::android::hardware::camera::device::BnCameraDeviceCallback;
using ::aidl::android::hardware::camera::device::BufferRequest;
using ::aidl::android::hardware::camera::device::BufferRequestStatus;
using ::aidl::android::hardware::camera::device::CaptureRequest;
using ::aidl::android::hardware::camera::device::CaptureResult;
using ::aidl::android::hardware::camera::device::HalStream;
using ::aidl::android::hardware::camera::device::NotifyMsg;
using ::aidl::android::hardware::camera::device::Stream;
using ::aidl::android::hardware::camera::device::StreamBuffer;
using ::aidl::android::hardware::camera::device::StreamBufferRet;
using ::aidl::android::hardware::camera::device::StreamConfiguration;
using ::aidl::android::hardware::graphics::common::PixelFormat;
using ::aidl::android::view::Surface;
using ::android::hardware::camera::common::helper::CameraMetadata;
using ::testing::_;
using ::testing::ElementsAre;
using ::testing::Eq;
using ::testing::IsNull;
using ::testing::NotNull;
using ::testing::Optional;
using ::testing::Return;
using ::testing::SizeIs;

Stream createStream(int streamId, int width, int height, PixelFormat format) {
  Stream s;
  s.id = streamId;
  s.width = width;
  s.height = height;
  s.format = format;
  return s;
}

Stream createHeicStream(int streamId, int width, int height) {
  Stream s = createStream(streamId, width, height, PixelFormat::BLOB);
  s.dataSpace = ::aidl::android::hardware::graphics::common::Dataspace::HEIF;
  return s;
}

Stream createJpegStream(int streamId, int width, int height) {
  Stream s = createStream(streamId, width, height, PixelFormat::BLOB);
  s.dataSpace = ::aidl::android::hardware::graphics::common::Dataspace::JFIF;
  return s;
}

class MockCameraDeviceCallback : public BnCameraDeviceCallback {
 public:
  MOCK_METHOD(ndk::ScopedAStatus, notify, (const std::vector<NotifyMsg>&),
              (override));
  MOCK_METHOD(ndk::ScopedAStatus, processCaptureResult,
              (const std::vector<CaptureResult>&), (override));
  MOCK_METHOD(ndk::ScopedAStatus, requestStreamBuffers,
              (const std::vector<BufferRequest>&, std::vector<StreamBufferRet>*,
               BufferRequestStatus*),
              (override));
  MOCK_METHOD(ndk::ScopedAStatus, returnStreamBuffers,
              (const std::vector<StreamBuffer>&), (override));
};

class MockVirtualCameraCallback : public BnVirtualCameraCallback {
 public:
  MOCK_METHOD(ndk::ScopedAStatus, onOpenCamera, (), (override));
  MOCK_METHOD(
      ndk::ScopedAStatus, onConfigureSession,
      (const VirtualCameraMetadata& in_sessionParameters,
       const std::shared_ptr<ICaptureResultConsumer>& in_captureResultConsumer),
      (override));
  MOCK_METHOD(ndk::ScopedAStatus, onStreamConfigured,
              (int, const Surface&, int32_t, int32_t, Format), (override));
  MOCK_METHOD(ndk::ScopedAStatus, onProcessCaptureRequest,
              (int, int, const std::optional<VirtualCameraMetadata>&),
              (override));
  MOCK_METHOD(ndk::ScopedAStatus, onStreamClosed, (int), (override));
};

class VirtualCameraSessionTestBase : public ::testing::Test {
 public:
  virtual void SetUp() override {
    mMockCameraDeviceCallback =
        ndk::SharedRefBase::make<MockCameraDeviceCallback>();
    mMockVirtualCameraClientCallback =
        ndk::SharedRefBase::make<MockVirtualCameraCallback>();

    // Explicitly defining default actions below to prevent gmock from
    // default-constructing ndk::ScopedAStatus, because default-constructed
    // status wraps nullptr AStatus and causes crash when attempting to print
    // it in gtest report.
    ON_CALL(*mMockCameraDeviceCallback, notify)
        .WillByDefault(ndk::ScopedAStatus::ok);
    ON_CALL(*mMockCameraDeviceCallback, processCaptureResult)
        .WillByDefault(ndk::ScopedAStatus::ok);
    ON_CALL(*mMockCameraDeviceCallback, requestStreamBuffers)
        .WillByDefault(ndk::ScopedAStatus::ok);
    ON_CALL(*mMockCameraDeviceCallback, returnStreamBuffers)
        .WillByDefault(ndk::ScopedAStatus::ok);

    ON_CALL(*mMockVirtualCameraClientCallback, onConfigureSession)
        .WillByDefault(ndk::ScopedAStatus::ok);
    ON_CALL(*mMockVirtualCameraClientCallback, onStreamConfigured)
        .WillByDefault(ndk::ScopedAStatus::ok);
    ON_CALL(*mMockVirtualCameraClientCallback, onProcessCaptureRequest)
        .WillByDefault(ndk::ScopedAStatus::ok);
    ON_CALL(*mMockVirtualCameraClientCallback, onStreamClosed)
        .WillByDefault(ndk::ScopedAStatus::ok);
  }

 protected:
  std::shared_ptr<MockCameraDeviceCallback> mMockCameraDeviceCallback;
  std::shared_ptr<MockVirtualCameraCallback> mMockVirtualCameraClientCallback;
};

class VirtualCameraSessionTest : public VirtualCameraSessionTestBase {
 public:
  void SetUp() override {
    VirtualCameraSessionTestBase::SetUp();

    mVirtualCameraDevice = ndk::SharedRefBase::make<VirtualCameraDevice>(
        kCameraId,
        VirtualCameraConfiguration{
            .supportedStreamConfigs = {SupportedStreamConfiguration{
                                           .width = kVgaWidth,
                                           .height = kVgaHeight,
                                           .imageFormat = Format::YUV_420_888,
                                           .maxFps = kMaxFps},
                                       SupportedStreamConfiguration{
                                           .width = kSvgaWidth,
                                           .height = kSvgaHeight,
                                           .imageFormat = Format::YUV_420_888,
                                           .maxFps = kMaxFps}},
            .virtualCameraCallback = mMockVirtualCameraClientCallback,
            .sensorOrientation = SensorOrientation::ORIENTATION_0,
            .lensFacing = LensFacing::FRONT},
        kDefaultDeviceId);
    mVirtualCameraSession = ndk::SharedRefBase::make<VirtualCameraSession>(
        mVirtualCameraDevice, mMockCameraDeviceCallback,
        mMockVirtualCameraClientCallback);
  }

 protected:
  std::shared_ptr<VirtualCameraDevice> mVirtualCameraDevice;
  std::shared_ptr<VirtualCameraSession> mVirtualCameraSession;
};

class VirtualCameraSessionInputChoiceTest : public VirtualCameraSessionTestBase {
 public:
  std::shared_ptr<VirtualCameraSession> createSession(
      const std::vector<SupportedStreamConfiguration>& supportedInputConfigs) {
    mVirtualCameraDevice = ndk::SharedRefBase::make<VirtualCameraDevice>(
        kCameraId,
        VirtualCameraConfiguration{
            .supportedStreamConfigs = supportedInputConfigs,
            .virtualCameraCallback = mMockVirtualCameraClientCallback,
            .sensorOrientation = SensorOrientation::ORIENTATION_0,
            .lensFacing = LensFacing::FRONT},
        kDefaultDeviceId);
    return ndk::SharedRefBase::make<VirtualCameraSession>(
        mVirtualCameraDevice, mMockCameraDeviceCallback,
        mMockVirtualCameraClientCallback);
  }

 protected:
  std::shared_ptr<VirtualCameraDevice> mVirtualCameraDevice;
};

class VirtualCameraSessionWithMetadata : public VirtualCameraSessionTestBase {
 public:
  std::shared_ptr<VirtualCameraSession> createMetadataSession(
      bool perFrameMetadataEnabled) {
    mVirtualCameraDevice = ndk::SharedRefBase::make<VirtualCameraDevice>(
        kCameraId,
        VirtualCameraConfiguration{
            .supportedStreamConfigs = {SupportedStreamConfiguration{
                .width = kVgaWidth,
                .height = kVgaHeight,
                .imageFormat = Format::YUV_420_888,
                .maxFps = kMaxFps}},
            .virtualCameraCallback = mMockVirtualCameraClientCallback,
            .sensorOrientation = SensorOrientation::ORIENTATION_0,
            .lensFacing = LensFacing::FRONT,
            .perFrameCameraMetadataEnabled = perFrameMetadataEnabled},
        kDefaultDeviceId);
    return ndk::SharedRefBase::make<VirtualCameraSession>(
        mVirtualCameraDevice, mMockCameraDeviceCallback,
        mMockVirtualCameraClientCallback);
  }

  std::shared_ptr<VirtualCameraSession> createMetadataSessionWithCharacteristics(
      bool perFrameMetadataEnabled) {
    auto lensFacingVec = std::vector<int32_t>({ANDROID_LENS_FACING_FRONT});
    auto sensorOrientationVec = std::vector<int32_t>(
        {static_cast<const int>(SensorOrientation::ORIENTATION_0)});
    CameraMetadata metadataHelper = CameraMetadata();
    metadataHelper.update(ANDROID_LENS_FACING, lensFacingVec.data(),
                          lensFacingVec.size());
    metadataHelper.update(ANDROID_SENSOR_ORIENTATION,
                          sensorOrientationVec.data(),
                          sensorOrientationVec.size());
    auto deviceCameraMetadata = cameraMetadataToHal(metadataHelper);

    VirtualCameraMetadata cameraCharacteristics;
    convertDeviceToVirtualCameraMetadata(*deviceCameraMetadata,
                                         cameraCharacteristics);

    mVirtualCameraDevice = ndk::SharedRefBase::make<VirtualCameraDevice>(
        kCameraId,
        VirtualCameraConfiguration{
            .supportedStreamConfigs = {SupportedStreamConfiguration{
                .width = kVgaWidth,
                .height = kVgaHeight,
                .imageFormat = Format::YUV_420_888,
                .maxFps = kMaxFps}},
            .virtualCameraCallback = mMockVirtualCameraClientCallback,
            .perFrameCameraMetadataEnabled = perFrameMetadataEnabled,
            .cameraCharacteristics = cameraCharacteristics},
        kDeviceId);
    return ndk::SharedRefBase::make<VirtualCameraSession>(
        mVirtualCameraDevice, mMockCameraDeviceCallback,
        mMockVirtualCameraClientCallback);
  }

 protected:
  std::shared_ptr<VirtualCameraDevice> mVirtualCameraDevice;
};

// Base Virtual Camera Session Tests

TEST_F(VirtualCameraSessionTest, ConfigureTriggersClientConfigureCallback) {
  PixelFormat format = PixelFormat::YCBCR_420_888;
  StreamConfiguration streamConfiguration;
  streamConfiguration.streams = {
      createStream(kStreamId, kVgaWidth, kVgaHeight, format),
      createStream(kSecondStreamId, kSvgaWidth, kSvgaHeight, format)};
  std::vector<HalStream> halStreams;

  // Expect highest resolution to be picked for the client input.
  EXPECT_CALL(
      *mMockVirtualCameraClientCallback,
      onStreamConfigured(0, _, kSvgaWidth, kSvgaHeight, Format::YUV_420_888));

  ASSERT_TRUE(
      mVirtualCameraSession->configureStreams(streamConfiguration, &halStreams)
          .isOk());

  EXPECT_THAT(halStreams, SizeIs(streamConfiguration.streams.size()));
  EXPECT_THAT(mVirtualCameraSession->getStreamIds(),
              ElementsAre(kStreamId, kSecondStreamId));
}

TEST_F(VirtualCameraSessionTest, SecondConfigureDropsUnreferencedStreams) {
  PixelFormat format = PixelFormat::YCBCR_420_888;
  StreamConfiguration streamConfiguration;
  std::vector<HalStream> halStreams;

  streamConfiguration.streams = {createStream(0, kVgaWidth, kVgaHeight, format),
                                 createStream(1, kVgaWidth, kVgaHeight, format),
                                 createStream(2, kVgaWidth, kVgaHeight, format)};
  ASSERT_TRUE(
      mVirtualCameraSession->configureStreams(streamConfiguration, &halStreams)
          .isOk());

  EXPECT_THAT(mVirtualCameraSession->getStreamIds(), ElementsAre(0, 1, 2));

  streamConfiguration.streams = {createStream(0, kVgaWidth, kVgaHeight, format),
                                 createStream(2, kVgaWidth, kVgaHeight, format),
                                 createStream(3, kVgaWidth, kVgaHeight, format)};
  ASSERT_TRUE(
      mVirtualCameraSession->configureStreams(streamConfiguration, &halStreams)
          .isOk());

  EXPECT_THAT(mVirtualCameraSession->getStreamIds(), ElementsAre(0, 2, 3));
}

TEST_F(VirtualCameraSessionTest, CloseTriggersClientTerminateCallback) {
  // First, configure a stream.
  PixelFormat format = PixelFormat::YCBCR_420_888;
  StreamConfiguration streamConfiguration;
  streamConfiguration.streams = {
      createStream(kStreamId, kVgaWidth, kVgaHeight, format)};
  std::vector<HalStream> halStreams;
  ASSERT_TRUE(
      mVirtualCameraSession->configureStreams(streamConfiguration, &halStreams)
          .isOk());

  EXPECT_CALL(*mMockVirtualCameraClientCallback, onStreamClosed(kStreamId))
      .WillOnce(Return(ndk::ScopedAStatus::ok()));

  ASSERT_TRUE(mVirtualCameraSession->close().isOk());
}

TEST_F(VirtualCameraSessionTest, FlushBeforeConfigure) {
  // Flush request coming before the configure request finished
  // (so potentially the thread is not yet running) should be
  // gracefully handled.

  EXPECT_TRUE(mVirtualCameraSession->flush().isOk());
}

TEST_F(VirtualCameraSessionTest, onProcessCaptureRequestTriggersClientCallback) {
  StreamConfiguration streamConfiguration;
  streamConfiguration.streams = {createStream(kStreamId, kVgaWidth, kVgaHeight,
                                              PixelFormat::YCBCR_420_888)};
  std::vector<CaptureRequest> requests(1);
  requests[0].frameNumber = 42;
  requests[0].settings = *(
      MetadataBuilder().setControlAfMode(ANDROID_CONTROL_AF_MODE_AUTO).build());

  std::vector<HalStream> halStreams;
  ASSERT_TRUE(
      mVirtualCameraSession->configureStreams(streamConfiguration, &halStreams)
          .isOk());

  EXPECT_CALL(*mMockVirtualCameraClientCallback,
              onProcessCaptureRequest(kStreamId, requests[0].frameNumber,
                                      Eq(std::nullopt)))
      .WillOnce(Return(ndk::ScopedAStatus::ok()));
  int32_t aidlReturn = 0;
  ASSERT_TRUE(mVirtualCameraSession
                  ->processCaptureRequest(requests, /*in_cachesToRemove=*/{},
                                          &aidlReturn)
                  .isOk());
  EXPECT_THAT(aidlReturn, Eq(requests.size()));
}

TEST_F(VirtualCameraSessionTest, configureAfterCameraRelease) {
  StreamConfiguration streamConfiguration;
  streamConfiguration.streams = {createStream(kStreamId, kVgaWidth, kVgaHeight,
                                              PixelFormat::YCBCR_420_888)};
  std::vector<HalStream> halStreams;

  // Release virtual camera.
  mVirtualCameraDevice.reset();

  // Expect configuration attempt returns CAMERA_DISCONNECTED service specific code.
  EXPECT_THAT(
      mVirtualCameraSession->configureStreams(streamConfiguration, &halStreams)
          .getServiceSpecificError(),
      Eq(static_cast<int32_t>(Status::CAMERA_DISCONNECTED)));
}

TEST_F(VirtualCameraSessionTest, ConfigureWithEmptyStreams) {
  StreamConfiguration streamConfiguration;
  std::vector<HalStream> halStreams;

  // Expect configuration attempt returns CAMERA_DISCONNECTED service specific code.
  EXPECT_THAT(
      mVirtualCameraSession->configureStreams(streamConfiguration, &halStreams)
          .getServiceSpecificError(),
      Eq(static_cast<int32_t>(Status::ILLEGAL_ARGUMENT)));
}

TEST_F(VirtualCameraSessionTest, ConfigureWithDifferentAspectRatioFails) {
  StreamConfiguration streamConfiguration;
  streamConfiguration.streams = {
      createStream(kStreamId, kVgaWidth, kVgaHeight, PixelFormat::YCBCR_420_888),
      createStream(kSecondStreamId, kVgaHeight, kVgaWidth,
                   PixelFormat::YCBCR_420_888)};

  std::vector<HalStream> halStreams;

  // Expect configuration attempt returns CAMERA_DISCONNECTED service specific code.
  EXPECT_THAT(
      mVirtualCameraSession->configureStreams(streamConfiguration, &halStreams)
          .getServiceSpecificError(),
      Eq(static_cast<int32_t>(Status::ILLEGAL_ARGUMENT)));
}

// Input Choice Virtual Camera Session Tests

TEST_F(VirtualCameraSessionInputChoiceTest,
       configureChoosesCorrectInputStreamForDownsampledOutput) {
  // Create camera configured to support SVGA YUV input and RGB QVGA input.
  auto virtualCameraSession = createSession(
      {SupportedStreamConfiguration{.width = kSvgaWidth,
                                    .height = kSvgaHeight,
                                    .imageFormat = Format::YUV_420_888,
                                    .maxFps = kMaxFps},
       SupportedStreamConfiguration{.width = kQvgaWidth,
                                    .height = kQvgaHeight,
                                    .imageFormat = Format::RGBA_8888,
                                    .maxFps = kMaxFps}});

  // Configure VGA stream. Expect SVGA input to be chosen to downscale from.
  StreamConfiguration streamConfiguration;
  streamConfiguration.streams = {createStream(
      kStreamId, kVgaWidth, kVgaHeight, PixelFormat::IMPLEMENTATION_DEFINED)};
  std::vector<HalStream> halStreams;

  // Expect configuration attempt returns CAMERA_DISCONNECTED service specific code.
  EXPECT_CALL(*mMockVirtualCameraClientCallback,
              onStreamConfigured(kStreamId, _, kSvgaWidth, kSvgaHeight,
                                 Format::YUV_420_888));
  EXPECT_TRUE(
      virtualCameraSession->configureStreams(streamConfiguration, &halStreams)
          .isOk());
}

TEST_F(VirtualCameraSessionInputChoiceTest,
       configureChoosesCorrectInputStreamForMatchingResolution) {
  // Create camera configured to support SVGA YUV input and RGB QVGA input.
  auto virtualCameraSession = createSession(
      {SupportedStreamConfiguration{.width = kSvgaWidth,
                                    .height = kSvgaHeight,
                                    .imageFormat = Format::YUV_420_888,
                                    .maxFps = kMaxFps},
       SupportedStreamConfiguration{.width = kQvgaWidth,
                                    .height = kQvgaHeight,
                                    .imageFormat = Format::RGBA_8888,
                                    .maxFps = kMaxFps}});

  // Configure VGA stream. Expect SVGA input to be chosen to downscale from.
  StreamConfiguration streamConfiguration;
  streamConfiguration.streams = {createStream(
      kStreamId, kQvgaWidth, kQvgaHeight, PixelFormat::IMPLEMENTATION_DEFINED)};
  std::vector<HalStream> halStreams;

  // Expect configuration attempt returns CAMERA_DISCONNECTED service specific code.
  EXPECT_CALL(*mMockVirtualCameraClientCallback,
              onStreamConfigured(kStreamId, _, kQvgaWidth, kQvgaHeight,
                                 Format::RGBA_8888));
  EXPECT_TRUE(
      virtualCameraSession->configureStreams(streamConfiguration, &halStreams)
          .isOk());
}

TEST_F_WITH_FLAGS(
    VirtualCameraSessionInputChoiceTest, heicBasicSingleInputSelection,
    REQUIRES_FLAGS_ENABLED(ACONFIG_FLAG(android::companion::virtualdevice::flags,
                                        virtual_camera_direct_blob_transfer))) {
  auto virtualCameraSession =
      createSession({SupportedStreamConfiguration{.width = kSvgaWidth,
                                                  .height = kSvgaHeight,
                                                  .imageFormat = Format::HEIC,
                                                  .maxFps = kMaxFps}});
  std::vector<HalStream> halStreams;
  StreamConfiguration streamConfiguration;
  streamConfiguration.streams = {
      createHeicStream(kStreamId, kSvgaWidth, kSvgaHeight)};
  EXPECT_CALL(
      *mMockVirtualCameraClientCallback,
      onStreamConfigured(kStreamId, _, kSvgaWidth, kSvgaHeight, Format::HEIC));
  EXPECT_TRUE(
      virtualCameraSession->configureStreams(streamConfiguration, &halStreams)
          .isOk());
}

TEST_F_WITH_FLAGS(VirtualCameraSessionInputChoiceTest,
                  heicBasicSingleInputSelectionFailWithoutFlagEnabled,
                  REQUIRES_FLAGS_DISABLED(
                      ACONFIG_FLAG(android::companion::virtualdevice::flags,
                                   virtual_camera_direct_blob_transfer))) {
  auto virtualCameraSession =
      createSession({SupportedStreamConfiguration{.width = kSvgaWidth,
                                                  .height = kSvgaHeight,
                                                  .imageFormat = Format::HEIC,
                                                  .maxFps = kMaxFps}});
  std::vector<HalStream> halStreams;
  StreamConfiguration streamConfiguration;
  streamConfiguration.streams = {
      createHeicStream(kStreamId, kSvgaWidth, kSvgaHeight)};
  EXPECT_THAT(
      virtualCameraSession->configureStreams(streamConfiguration, &halStreams)
          .getServiceSpecificError(),
      Eq(static_cast<int32_t>(Status::ILLEGAL_ARGUMENT)));
}

TEST_F_WITH_FLAGS(
    VirtualCameraSessionInputChoiceTest, heicMultipleInputSelection,
    REQUIRES_FLAGS_ENABLED(ACONFIG_FLAG(android::companion::virtualdevice::flags,
                                        virtual_camera_direct_blob_transfer))) {
  auto virtualCameraSession =
      createSession({SupportedStreamConfiguration{.width = kSvgaWidth,
                                                  .height = kSvgaHeight,
                                                  .imageFormat = Format::HEIC,
                                                  .maxFps = kMaxFps},
                     SupportedStreamConfiguration{.width = kVgaWidth,
                                                  .height = kVgaHeight,
                                                  .imageFormat = Format::HEIC,
                                                  .maxFps = kMaxFps}});
  std::vector<HalStream> halStreams;
  StreamConfiguration streamConfiguration;
  streamConfiguration.streams = {
      createHeicStream(kStreamId, kSvgaWidth, kSvgaHeight)};
  EXPECT_CALL(
      *mMockVirtualCameraClientCallback,
      onStreamConfigured(kStreamId, _, kSvgaWidth, kSvgaHeight, Format::HEIC));
  EXPECT_TRUE(
      virtualCameraSession->configureStreams(streamConfiguration, &halStreams)
          .isOk());

  streamConfiguration.streams = {
      createHeicStream(kStreamId + 1, kVgaWidth, kVgaHeight)};
  EXPECT_CALL(*mMockVirtualCameraClientCallback,
              onStreamConfigured(kStreamId + 1, _, kVgaWidth, kVgaHeight,
                                 Format::HEIC));
  EXPECT_TRUE(
      virtualCameraSession->configureStreams(streamConfiguration, &halStreams)
          .isOk());
}

TEST_F_WITH_FLAGS(VirtualCameraSessionInputChoiceTest,
                  heicResolutionMismatchInputSelectionFail,
                  REQUIRES_FLAGS_ENABLED(
                      ACONFIG_FLAG(android::companion::virtualdevice::flags,
                                   virtual_camera_direct_blob_transfer))) {
  auto virtualCameraSession =
      createSession({SupportedStreamConfiguration{.width = kSvgaWidth,
                                                  .height = kSvgaHeight,
                                                  .imageFormat = Format::HEIC,
                                                  .maxFps = kMaxFps}});
  std::vector<HalStream> halStreams;
  StreamConfiguration streamConfiguration;
  streamConfiguration.streams = {
      createHeicStream(kStreamId, kQvgaWidth, kQvgaHeight)};
  EXPECT_THAT(
      virtualCameraSession->configureStreams(streamConfiguration, &halStreams)
          .getServiceSpecificError(),
      Eq(static_cast<int32_t>(Status::ILLEGAL_ARGUMENT)));

  streamConfiguration.streams = {
      createHeicStream(kStreamId, kVgaWidth, kVgaHeight)};
  EXPECT_THAT(
      virtualCameraSession->configureStreams(streamConfiguration, &halStreams)
          .getServiceSpecificError(),
      Eq(static_cast<int32_t>(Status::ILLEGAL_ARGUMENT)));
}

TEST_F_WITH_FLAGS(
    VirtualCameraSessionInputChoiceTest, heicFormatMismatchInputSelectionFail,
    REQUIRES_FLAGS_ENABLED(ACONFIG_FLAG(android::companion::virtualdevice::flags,
                                        virtual_camera_direct_blob_transfer))) {
  auto virtualCameraSession =
      createSession({SupportedStreamConfiguration{.width = kSvgaWidth,
                                                  .height = kSvgaHeight,
                                                  .imageFormat = Format::HEIC,
                                                  .maxFps = kMaxFps}});
  std::vector<HalStream> halStreams;
  StreamConfiguration streamConfiguration;
  streamConfiguration.streams = {
      createJpegStream(kStreamId, kSvgaWidth, kSvgaHeight)};
  EXPECT_THAT(
      virtualCameraSession->configureStreams(streamConfiguration, &halStreams)
          .getServiceSpecificError(),
      Eq(static_cast<int32_t>(Status::ILLEGAL_ARGUMENT)));

  streamConfiguration.streams = {createStream(
      kStreamId, kSvgaWidth, kSvgaHeight, PixelFormat::YCBCR_420_888)};
  EXPECT_THAT(
      virtualCameraSession->configureStreams(streamConfiguration, &halStreams)
          .getServiceSpecificError(),
      Eq(static_cast<int32_t>(Status::ILLEGAL_ARGUMENT)));
}

TEST_F_WITH_FLAGS(
    VirtualCameraSessionInputChoiceTest, jpegBasicSingleInputSelection,
    REQUIRES_FLAGS_ENABLED(ACONFIG_FLAG(android::companion::virtualdevice::flags,
                                        virtual_camera_direct_blob_transfer))) {
  auto virtualCameraSession =
      createSession({SupportedStreamConfiguration{.width = kSvgaWidth,
                                                  .height = kSvgaHeight,
                                                  .imageFormat = Format::JPEG,
                                                  .maxFps = kMaxFps}});
  std::vector<HalStream> halStreams;
  StreamConfiguration streamConfiguration;
  streamConfiguration.streams = {
      createJpegStream(kStreamId, kSvgaWidth, kSvgaHeight)};
  EXPECT_CALL(
      *mMockVirtualCameraClientCallback,
      onStreamConfigured(kStreamId, _, kSvgaWidth, kSvgaHeight, Format::JPEG));
  EXPECT_TRUE(
      virtualCameraSession->configureStreams(streamConfiguration, &halStreams)
          .isOk());
}

TEST_F_WITH_FLAGS(VirtualCameraSessionInputChoiceTest,
                  jpegBasicSingleInputSelectionFailWithoutFlagEnabled,
                  REQUIRES_FLAGS_DISABLED(
                      ACONFIG_FLAG(android::companion::virtualdevice::flags,
                                   virtual_camera_direct_blob_transfer))) {
  auto virtualCameraSession =
      createSession({SupportedStreamConfiguration{.width = kSvgaWidth,
                                                  .height = kSvgaHeight,
                                                  .imageFormat = Format::JPEG,
                                                  .maxFps = kMaxFps}});
  std::vector<HalStream> halStreams;
  StreamConfiguration streamConfiguration;
  streamConfiguration.streams = {
      createJpegStream(kStreamId, kSvgaWidth, kSvgaHeight)};
  EXPECT_THAT(
      virtualCameraSession->configureStreams(streamConfiguration, &halStreams)
          .getServiceSpecificError(),
      Eq(static_cast<int32_t>(Status::ILLEGAL_ARGUMENT)));
}

TEST_F_WITH_FLAGS(
    VirtualCameraSessionInputChoiceTest, jpegMultipleInputSelection,
    REQUIRES_FLAGS_ENABLED(ACONFIG_FLAG(android::companion::virtualdevice::flags,
                                        virtual_camera_direct_blob_transfer))) {
  auto virtualCameraSession =
      createSession({SupportedStreamConfiguration{.width = kSvgaWidth,
                                                  .height = kSvgaHeight,
                                                  .imageFormat = Format::JPEG,
                                                  .maxFps = kMaxFps},
                     SupportedStreamConfiguration{.width = kVgaWidth,
                                                  .height = kVgaHeight,
                                                  .imageFormat = Format::JPEG,
                                                  .maxFps = kMaxFps}});
  std::vector<HalStream> halStreams;
  StreamConfiguration streamConfiguration;
  streamConfiguration.streams = {
      createJpegStream(kStreamId, kSvgaWidth, kSvgaHeight)};
  EXPECT_CALL(
      *mMockVirtualCameraClientCallback,
      onStreamConfigured(kStreamId, _, kSvgaWidth, kSvgaHeight, Format::JPEG));
  EXPECT_TRUE(
      virtualCameraSession->configureStreams(streamConfiguration, &halStreams)
          .isOk());

  streamConfiguration.streams = {
      createJpegStream(kStreamId + 1, kVgaWidth, kVgaHeight)};
  EXPECT_CALL(*mMockVirtualCameraClientCallback,
              onStreamConfigured(kStreamId + 1, _, kVgaWidth, kVgaHeight,
                                 Format::JPEG));
  EXPECT_TRUE(
      virtualCameraSession->configureStreams(streamConfiguration, &halStreams)
          .isOk());
}

TEST_F_WITH_FLAGS(VirtualCameraSessionInputChoiceTest,
                  jpegResolutionMismatchInputSelectionFail,
                  REQUIRES_FLAGS_ENABLED(
                      ACONFIG_FLAG(android::companion::virtualdevice::flags,
                                   virtual_camera_direct_blob_transfer))) {
  auto virtualCameraSession =
      createSession({SupportedStreamConfiguration{.width = kSvgaWidth,
                                                  .height = kSvgaHeight,
                                                  .imageFormat = Format::HEIC,
                                                  .maxFps = kMaxFps}});
  std::vector<HalStream> halStreams;
  StreamConfiguration streamConfiguration;
  streamConfiguration.streams = {
      createHeicStream(kStreamId, kQvgaWidth, kQvgaHeight)};
  EXPECT_THAT(
      virtualCameraSession->configureStreams(streamConfiguration, &halStreams)
          .getServiceSpecificError(),
      Eq(static_cast<int32_t>(Status::ILLEGAL_ARGUMENT)));

  streamConfiguration.streams = {
      createHeicStream(kStreamId, kVgaWidth, kVgaHeight)};
  EXPECT_THAT(
      virtualCameraSession->configureStreams(streamConfiguration, &halStreams)
          .getServiceSpecificError(),
      Eq(static_cast<int32_t>(Status::ILLEGAL_ARGUMENT)));
}

TEST_F_WITH_FLAGS(
    VirtualCameraSessionInputChoiceTest, jpegFormatMismatchInputSelectionFail,
    REQUIRES_FLAGS_ENABLED(ACONFIG_FLAG(android::companion::virtualdevice::flags,
                                        virtual_camera_direct_blob_transfer))) {
  auto virtualCameraSession =
      createSession({SupportedStreamConfiguration{.width = kSvgaWidth,
                                                  .height = kSvgaHeight,
                                                  .imageFormat = Format::JPEG,
                                                  .maxFps = kMaxFps}});
  std::vector<HalStream> halStreams;
  StreamConfiguration streamConfiguration;
  streamConfiguration.streams = {
      createHeicStream(kStreamId, kSvgaWidth, kSvgaHeight)};
  EXPECT_THAT(
      virtualCameraSession->configureStreams(streamConfiguration, &halStreams)
          .getServiceSpecificError(),
      Eq(static_cast<int32_t>(Status::ILLEGAL_ARGUMENT)));

  streamConfiguration.streams = {createStream(
      kStreamId, kSvgaWidth, kSvgaHeight, PixelFormat::YCBCR_420_888)};
  EXPECT_THAT(
      virtualCameraSession->configureStreams(streamConfiguration, &halStreams)
          .getServiceSpecificError(),
      Eq(static_cast<int32_t>(Status::ILLEGAL_ARGUMENT)));
}

TEST_F_WITH_FLAGS(
    VirtualCameraSessionInputChoiceTest, blobHeterogeneousInputSelection,
    REQUIRES_FLAGS_ENABLED(ACONFIG_FLAG(android::companion::virtualdevice::flags,
                                        virtual_camera_direct_blob_transfer))) {
  auto virtualCameraSession =
      createSession({SupportedStreamConfiguration{.width = kVgaWidth,
                                                  .height = kVgaHeight,
                                                  .imageFormat = Format::HEIC,
                                                  .maxFps = kMaxFps},
                     SupportedStreamConfiguration{.width = kVgaWidth,
                                                  .height = kVgaHeight,
                                                  .imageFormat = Format::JPEG,
                                                  .maxFps = kMaxFps}});
  std::vector<HalStream> halStreams;
  StreamConfiguration streamConfiguration;
  streamConfiguration.streams = {
      createHeicStream(kStreamId, kVgaWidth, kVgaHeight)};
  EXPECT_CALL(
      *mMockVirtualCameraClientCallback,
      onStreamConfigured(kStreamId, _, kVgaWidth, kVgaHeight, Format::HEIC));
  EXPECT_TRUE(
      virtualCameraSession->configureStreams(streamConfiguration, &halStreams)
          .isOk());

  streamConfiguration.streams = {
      createJpegStream(kStreamId + 1, kVgaWidth, kVgaHeight)};
  EXPECT_CALL(*mMockVirtualCameraClientCallback,
              onStreamConfigured(kStreamId + 1, _, kVgaWidth, kVgaHeight,
                                 Format::JPEG));

  EXPECT_CALL(*mMockVirtualCameraClientCallback, onStreamClosed(kStreamId));

  EXPECT_TRUE(
      virtualCameraSession->configureStreams(streamConfiguration, &halStreams)
          .isOk());
}

TEST_F(VirtualCameraSessionInputChoiceTest, reconfigureSwitchesInputStream) {
  // Create camera configured to support SVGA YUV input and RGB QVGA input.
  auto virtualCameraSession = createSession(
      {SupportedStreamConfiguration{.width = kSvgaWidth,
                                    .height = kSvgaHeight,
                                    .imageFormat = Format::YUV_420_888,
                                    .maxFps = kMaxFps},
       SupportedStreamConfiguration{.width = kQvgaWidth,
                                    .height = kQvgaHeight,
                                    .imageFormat = Format::RGBA_8888,
                                    .maxFps = kMaxFps}});

  // First configure QVGA stream.
  StreamConfiguration streamConfiguration;
  streamConfiguration.streams = {createStream(
      kStreamId, kQvgaWidth, kQvgaHeight, PixelFormat::IMPLEMENTATION_DEFINED)};
  std::vector<HalStream> halStreams;

  // Expect QVGA input configuragion to be chosen.
  EXPECT_CALL(*mMockVirtualCameraClientCallback,
              onStreamConfigured(kStreamId, _, kQvgaWidth, kQvgaHeight,
                                 Format::RGBA_8888));
  EXPECT_TRUE(
      virtualCameraSession->configureStreams(streamConfiguration, &halStreams)
          .isOk());

  // Reconfigure with additional VGA stream.
  streamConfiguration.streams.push_back(
      createStream(kStreamId + 1, kVgaWidth, kVgaHeight,
                   PixelFormat::IMPLEMENTATION_DEFINED));

  // Expect original surface to be discarded.
  EXPECT_CALL(*mMockVirtualCameraClientCallback, onStreamClosed(kStreamId));

  // Expect SVGA input configuragion to be chosen.
  EXPECT_CALL(*mMockVirtualCameraClientCallback,
              onStreamConfigured(kStreamId + 1, _, kSvgaWidth, kSvgaHeight,
                                 Format::YUV_420_888));
  EXPECT_TRUE(
      virtualCameraSession->configureStreams(streamConfiguration, &halStreams)
          .isOk());
}

TEST_F(VirtualCameraSessionInputChoiceTest,
       reconfigureKeepsInputStreamIfUnchanged) {
  // Create camera configured to support SVGA YUV input and RGB QVGA input.
  auto virtualCameraSession = createSession(
      {SupportedStreamConfiguration{.width = kSvgaWidth,
                                    .height = kSvgaHeight,
                                    .imageFormat = Format::YUV_420_888,
                                    .maxFps = kMaxFps},
       SupportedStreamConfiguration{.width = kQvgaWidth,
                                    .height = kQvgaHeight,
                                    .imageFormat = Format::RGBA_8888,
                                    .maxFps = kMaxFps}});

  // First configure SVGA stream.
  StreamConfiguration streamConfiguration;
  streamConfiguration.streams = {createStream(
      kStreamId, kSvgaWidth, kSvgaHeight, PixelFormat::IMPLEMENTATION_DEFINED)};
  std::vector<HalStream> halStreams;

  // Expect SVGA input configuragion to be chosen.
  EXPECT_CALL(*mMockVirtualCameraClientCallback,
              onStreamConfigured(kStreamId, _, kSvgaWidth, kSvgaHeight,
                                 Format::YUV_420_888));
  EXPECT_TRUE(
      virtualCameraSession->configureStreams(streamConfiguration, &halStreams)
          .isOk());

  // Reconfigure with VGA + QVA stream. Because we only allow downscaling,
  // this will be matched to SVGA input resolution.
  streamConfiguration.streams = {
      createStream(kStreamId + 1, kVgaWidth, kVgaHeight,
                   PixelFormat::IMPLEMENTATION_DEFINED),
      createStream(kStreamId + 2, kVgaWidth, kVgaHeight,
                   PixelFormat::IMPLEMENTATION_DEFINED)};

  // Expect the onStreamConfigured callback not to be invoked, since the
  // original Surface is still best fit for current output streams.
  EXPECT_CALL(*mMockVirtualCameraClientCallback, onStreamConfigured).Times(0);
  EXPECT_TRUE(
      virtualCameraSession->configureStreams(streamConfiguration, &halStreams)
          .isOk());
}

// Virtual Camera Session With Metadata Tests

TEST_F_WITH_FLAGS(VirtualCameraSessionWithMetadata,
                  onProcessCaptureRequestMetadataTriggersClientCallback,
                  REQUIRES_FLAGS_ENABLED(
                      ACONFIG_FLAG(android::companion::virtualdevice::flags,
                                   virtual_camera_metadata))) {
  auto virtualCameraSession =
      createMetadataSession(true /* perFrameMetadataEnabled */);

  StreamConfiguration streamConfiguration;
  streamConfiguration.streams = {createStream(kStreamId, kVgaWidth, kVgaHeight,
                                              PixelFormat::YCBCR_420_888)};
  streamConfiguration.sessionParams =
      *(MetadataBuilder()
            .setFlashAvailable(true)
            .setFocalLength(kFocalLength)
            .setControlAeTargetFpsRange(kFpsRange)
            .build());

  std::vector<CaptureRequest> requests(1);
  requests[0].frameNumber = 42;
  requests[0].settings = *(MetadataBuilder()
                               .setControlAfMode(ANDROID_CONTROL_AF_MODE_AUTO)
                               .setControlAeTargetFpsRange(kFpsRange)
                               .build());
  VirtualCameraMetadata expectedCaptureRequestSettings;
  convertDeviceToVirtualCameraMetadata(requests[0].settings,
                                       expectedCaptureRequestSettings);
  VirtualCameraMetadata expectedSessionParams;
  convertDeviceToVirtualCameraMetadata(streamConfiguration.sessionParams,
                                       expectedSessionParams);

  CaptureResult captureResult;
  captureResult.result = *(MetadataBuilder()
                               .setControlMode(ANDROID_CONTROL_MODE_AUTO)
                               .setControlAeTargetFpsRange(kFpsRange)
                               .build());
  VirtualCameraMetadata captureResultVirtualMetadata;
  convertDeviceToVirtualCameraMetadata(captureResult.result,
                                       captureResultVirtualMetadata);

  std::shared_ptr<ICaptureResultConsumer> captureResultConsumer;
  EXPECT_CALL(*mMockVirtualCameraClientCallback,
              onConfigureSession(expectedSessionParams, NotNull()))
      .WillOnce([&](const VirtualCameraMetadata&,
                    const std::shared_ptr<ICaptureResultConsumer>&
                        in_captureResultConsumer) {
        captureResultConsumer = in_captureResultConsumer;
        return ndk::ScopedAStatus::ok();
      });

  std::vector<HalStream> halStreams;
  ASSERT_TRUE(
      virtualCameraSession->configureStreams(streamConfiguration, &halStreams)
          .isOk());

  EXPECT_CALL(*mMockVirtualCameraClientCallback,
              onProcessCaptureRequest(kStreamId, requests[0].frameNumber,
                                      Optional(expectedCaptureRequestSettings)))
      .WillOnce(Return(ndk::ScopedAStatus::ok()));

  int32_t aidlReturn = 0;
  ASSERT_TRUE(virtualCameraSession
                  ->processCaptureRequest(requests, /*in_cachesToRemove=*/{},
                                          &aidlReturn)
                  .isOk());
  EXPECT_THAT(aidlReturn, Eq(requests.size()));

  ASSERT_TRUE(captureResultConsumer
                  ->acceptCaptureResult(100L, captureResultVirtualMetadata)
                  .isOk());
}

TEST_F_WITH_FLAGS(
    VirtualCameraSessionWithMetadata,
    onProcessCaptureRequestMetadataTriggersClientCallbackNoPerFrameMetadata,
    REQUIRES_FLAGS_ENABLED(ACONFIG_FLAG(android::companion::virtualdevice::flags,
                                        virtual_camera_metadata))) {
  auto virtualCameraSession =
      createMetadataSession(false /* perFrameMetadataEnabled */);

  StreamConfiguration streamConfiguration;
  streamConfiguration.streams = {createStream(kStreamId, kVgaWidth, kVgaHeight,
                                              PixelFormat::YCBCR_420_888)};
  streamConfiguration.sessionParams =
      *(MetadataBuilder()
            .setFlashAvailable(true)
            .setFocalLength(kFocalLength)
            .setControlAeTargetFpsRange(kFpsRange)
            .build());

  std::vector<CaptureRequest> requests(1);
  requests[0].frameNumber = 42;
  requests[0].settings = *(MetadataBuilder()
                               .setControlAfMode(ANDROID_CONTROL_AF_MODE_AUTO)
                               .setControlAeTargetFpsRange(kFpsRange)
                               .build());

  VirtualCameraMetadata expectedSessionParams;
  convertDeviceToVirtualCameraMetadata(streamConfiguration.sessionParams,
                                       expectedSessionParams);

  EXPECT_CALL(*mMockVirtualCameraClientCallback,
              onConfigureSession(expectedSessionParams, IsNull()))
      .WillOnce(Return(ndk::ScopedAStatus::ok()));

  std::vector<HalStream> halStreams;
  ASSERT_TRUE(
      virtualCameraSession->configureStreams(streamConfiguration, &halStreams)
          .isOk());

  EXPECT_CALL(*mMockVirtualCameraClientCallback,
              onProcessCaptureRequest(kStreamId, requests[0].frameNumber,
                                      Eq(std::nullopt)))
      .WillOnce(Return(ndk::ScopedAStatus::ok()));

  int32_t aidlReturn = 0;
  ASSERT_TRUE(virtualCameraSession
                  ->processCaptureRequest(requests, /*in_cachesToRemove=*/{},
                                          &aidlReturn)
                  .isOk());
  EXPECT_THAT(aidlReturn, Eq(requests.size()));
}

TEST_F_WITH_FLAGS(
    VirtualCameraSessionWithMetadata,
    onProcessCaptureRequestMetadataWithCharacteristicsTriggersClientCallback,
    REQUIRES_FLAGS_ENABLED(ACONFIG_FLAG(android::companion::virtualdevice::flags,
                                        virtual_camera_metadata))) {
  auto virtualCameraSession = createMetadataSessionWithCharacteristics(
      true /* perFrameMetadataEnabled */);

  StreamConfiguration streamConfiguration;
  streamConfiguration.streams = {createStream(kStreamId, kVgaWidth, kVgaHeight,
                                              PixelFormat::YCBCR_420_888)};
  streamConfiguration.sessionParams =
      *(MetadataBuilder()
            .setFlashAvailable(true)
            .setFocalLength(kFocalLength)
            .setControlAeTargetFpsRange(kFpsRange)
            .build());

  std::vector<CaptureRequest> requests(1);
  requests[0].frameNumber = 42;
  requests[0].settings = *(MetadataBuilder()
                               .setControlAfMode(ANDROID_CONTROL_AF_MODE_AUTO)
                               .setControlAeTargetFpsRange(kFpsRange)
                               .build());

  VirtualCameraMetadata expectedCaptureRequestSettings;
  convertDeviceToVirtualCameraMetadata(requests[0].settings,
                                       expectedCaptureRequestSettings);
  VirtualCameraMetadata expectedSessionParams;
  convertDeviceToVirtualCameraMetadata(streamConfiguration.sessionParams,
                                       expectedSessionParams);

  CaptureResult captureResult;
  captureResult.result = *(MetadataBuilder()
                               .setControlMode(ANDROID_CONTROL_MODE_AUTO)
                               .setControlAeTargetFpsRange(kFpsRange)
                               .build());
  VirtualCameraMetadata captureResultVirtualMetadata;
  convertDeviceToVirtualCameraMetadata(captureResult.result,
                                       captureResultVirtualMetadata);

  std::shared_ptr<ICaptureResultConsumer> captureResultConsumer;
  EXPECT_CALL(*mMockVirtualCameraClientCallback,
              onConfigureSession(expectedSessionParams, NotNull()))
      .WillOnce([&](const VirtualCameraMetadata&,
                    const std::shared_ptr<ICaptureResultConsumer>&
                        in_captureResultConsumer) {
        captureResultConsumer = in_captureResultConsumer;
        return ndk::ScopedAStatus::ok();
      });

  std::vector<HalStream> halStreams;
  ASSERT_TRUE(
      virtualCameraSession->configureStreams(streamConfiguration, &halStreams)
          .isOk());

  EXPECT_CALL(*mMockVirtualCameraClientCallback,
              onProcessCaptureRequest(kStreamId, requests[0].frameNumber,
                                      Optional(expectedCaptureRequestSettings)))
      .WillOnce(Return(ndk::ScopedAStatus::ok()));

  int32_t aidlReturn = 0;
  ASSERT_TRUE(virtualCameraSession
                  ->processCaptureRequest(requests, /*in_cachesToRemove=*/{},
                                          &aidlReturn)
                  .isOk());
  EXPECT_THAT(aidlReturn, Eq(requests.size()));

  ASSERT_TRUE(captureResultConsumer
                  ->acceptCaptureResult(100L, captureResultVirtualMetadata)
                  .isOk());
}

TEST_F_WITH_FLAGS(
    VirtualCameraSessionWithMetadata,
    onProcessCaptureRequestMetadataWithCharacteristicsTriggersClientCallbackNoPerFrameMetadata,
    REQUIRES_FLAGS_ENABLED(ACONFIG_FLAG(android::companion::virtualdevice::flags,
                                        virtual_camera_metadata))) {
  auto virtualCameraSession = createMetadataSessionWithCharacteristics(
      false /* perFrameMetadataEnabled */);

  StreamConfiguration streamConfiguration;
  streamConfiguration.streams = {createStream(kStreamId, kVgaWidth, kVgaHeight,
                                              PixelFormat::YCBCR_420_888)};
  streamConfiguration.sessionParams =
      *(MetadataBuilder()
            .setFlashAvailable(true)
            .setFocalLength(kFocalLength)
            .setControlAeTargetFpsRange(kFpsRange)
            .build());

  std::vector<CaptureRequest> requests(1);
  requests[0].frameNumber = 42;
  requests[0].settings = *(MetadataBuilder()
                               .setControlAfMode(ANDROID_CONTROL_AF_MODE_AUTO)
                               .setControlAeTargetFpsRange(kFpsRange)
                               .build());

  VirtualCameraMetadata expectedSessionParams;
  convertDeviceToVirtualCameraMetadata(streamConfiguration.sessionParams,
                                       expectedSessionParams);

  EXPECT_CALL(*mMockVirtualCameraClientCallback,
              onConfigureSession(expectedSessionParams, IsNull()))
      .WillOnce(Return(ndk::ScopedAStatus::ok()));

  std::vector<HalStream> halStreams;
  ASSERT_TRUE(
      virtualCameraSession->configureStreams(streamConfiguration, &halStreams)
          .isOk());

  EXPECT_CALL(*mMockVirtualCameraClientCallback,
              onProcessCaptureRequest(kStreamId, requests[0].frameNumber,
                                      Eq(std::nullopt)))
      .WillOnce(Return(ndk::ScopedAStatus::ok()));

  int32_t aidlReturn = 0;
  ASSERT_TRUE(virtualCameraSession
                  ->processCaptureRequest(requests, /*in_cachesToRemove=*/{},
                                          &aidlReturn)
                  .isOk());
  EXPECT_THAT(aidlReturn, Eq(requests.size()));
}

}  // namespace
}  // namespace virtualcamera
}  // namespace companion
}  // namespace android
