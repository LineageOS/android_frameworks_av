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

#include <sys/cdefs.h>

#include <memory>

#include "VirtualCameraImagePassthroughHandler.h"
#include "VirtualCameraRenderThread.h"
#include "VirtualCameraSessionContext.h"
#include "aidl/android/companion/virtualcamera/Format.h"
#include "aidl/android/hardware/camera/common/CameraDeviceStatus.h"
#include "aidl/android/hardware/camera/common/TorchModeStatus.h"
#include "aidl/android/hardware/camera/device/BnCameraDeviceCallback.h"
#include "aidl/android/hardware/camera/device/BufferRequest.h"
#include "aidl/android/hardware/camera/device/BufferRequestStatus.h"
#include "aidl/android/hardware/camera/device/BufferStatus.h"
#include "aidl/android/hardware/camera/device/CameraBlob.h"
#include "aidl/android/hardware/camera/device/CameraBlobId.h"
#include "aidl/android/hardware/camera/device/CaptureResult.h"
#include "aidl/android/hardware/camera/device/NotifyMsg.h"
#include "aidl/android/hardware/camera/device/StreamBuffer.h"
#include "aidl/android/hardware/camera/device/StreamBufferRet.h"
#include "android/binder_auto_utils.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "util/Util.h"

namespace android {
namespace companion {
namespace virtualcamera {

using ::aidl::android::companion::virtualcamera::Format;
using ::aidl::android::hardware::camera::common::CameraDeviceStatus;
using ::aidl::android::hardware::camera::common::TorchModeStatus;
using ::aidl::android::hardware::camera::device::BnCameraDeviceCallback;
using ::aidl::android::hardware::camera::device::BufferRequest;
using ::aidl::android::hardware::camera::device::BufferRequestStatus;
using ::aidl::android::hardware::camera::device::BufferStatus;
using ::aidl::android::hardware::camera::device::CameraBlob;
using ::aidl::android::hardware::camera::device::CameraBlobId;
using ::aidl::android::hardware::camera::device::CaptureResult;
using ::aidl::android::hardware::camera::device::ErrorCode;
using ::aidl::android::hardware::camera::device::ErrorMsg;
using ::aidl::android::hardware::camera::device::NotifyMsg;
using ::aidl::android::hardware::camera::device::StreamBuffer;
using ::aidl::android::hardware::camera::device::StreamBufferRet;
using ::testing::AllOf;
using ::testing::ElementsAre;
using ::testing::Eq;
using ::testing::Field;
using ::testing::Matcher;
using ::testing::Property;
using ::testing::Return;
using ::testing::SizeIs;

constexpr Format kImageFormat = Format::YUV_420_888;
constexpr int kInputWidth = 640;
constexpr int kInputHeight = 480;
const Resolution kInputResolution(kInputWidth, kInputHeight);

Matcher<StreamBuffer> IsStreamBufferWithStatus(const int streamId,
                                               const int bufferId,
                                               const BufferStatus status) {
  return AllOf(Field(&StreamBuffer::streamId, Eq(streamId)),
               Field(&StreamBuffer::bufferId, Eq(bufferId)),
               Field(&StreamBuffer::status, Eq(status)));
}

Matcher<NotifyMsg> IsRequestErrorNotifyMsg(const int frameId) {
  return AllOf(Property(&NotifyMsg::getTag, Eq(NotifyMsg::error)),
               Property(&NotifyMsg::get<NotifyMsg::error>,
                        Field(&ErrorMsg::frameNumber, Eq(frameId))),
               Property(&NotifyMsg::get<NotifyMsg::error>,
                        Field(&ErrorMsg::errorStreamId, Eq(-1))),
               Property(&NotifyMsg::get<NotifyMsg::error>,
                        Field(&ErrorMsg::errorCode, Eq(ErrorCode::ERROR_REQUEST))));
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

class VirtualCameraRenderThreadTest : public ::testing::Test {
 public:
  void SetUp() override {
    mSessionContext = std::make_unique<VirtualCameraSessionContext>(false);
    mMockCameraDeviceCallback =
        ndk::SharedRefBase::make<MockCameraDeviceCallback>();
    mRenderThread = std::make_unique<VirtualCameraRenderThread>(
        *mSessionContext, kInvalidStreamId, kImageFormat, kInputResolution,
        /*reportedSensorSize*/ kInputResolution, mMockCameraDeviceCallback);
  }

  int32_t findActualPayloadSize(const uint8_t* buffer, int32_t size,
                                const Format format) {
    VirtualCameraImagePassthroughHandler handler(*mSessionContext, format,
                                                 nullptr, nullptr, nullptr);
    return handler.findActualPayloadSize(buffer, size, format);
  }

 protected:
  std::unique_ptr<VirtualCameraSessionContext> mSessionContext;
  std::unique_ptr<VirtualCameraRenderThread> mRenderThread;
  std::shared_ptr<MockCameraDeviceCallback> mMockCameraDeviceCallback;
};

namespace {

using ::aidl::android::companion::virtualcamera::Format;

TEST_F(VirtualCameraRenderThreadTest, FlushReturnsErrorForInFlightRequests) {
  const int frameNumber = 42;
  const int firstStreamId = 1;
  const int firstStreamBufferId = 1234;
  const int secondStreamId = 7;
  const int secondStreamBufferId = 4321;

  // Notify should be called with the error set to corresponding frame.
  EXPECT_CALL(*mMockCameraDeviceCallback,
              notify(ElementsAre(IsRequestErrorNotifyMsg(frameNumber))))
      .WillOnce(Return(ndk::ScopedAStatus::ok()));

  // Process capture result should be called with all buffers in error state.
  EXPECT_CALL(
      *mMockCameraDeviceCallback,
      processCaptureResult(ElementsAre(AllOf(
          Field(&CaptureResult::frameNumber, frameNumber),
          Field(&CaptureResult::outputBuffers,
                testing::UnorderedElementsAre(
                    IsStreamBufferWithStatus(firstStreamId, firstStreamBufferId,
                                             BufferStatus::ERROR),
                    IsStreamBufferWithStatus(secondStreamId, secondStreamBufferId,
                                             BufferStatus::ERROR)))))))
      .WillOnce([]() { return ndk::ScopedAStatus::ok(); });

  mRenderThread->enqueueTask(std::make_unique<ProcessCaptureRequestTask>(
      frameNumber,
      std::vector<CaptureRequestBuffer>{
          CaptureRequestBuffer(firstStreamId, firstStreamBufferId),
          CaptureRequestBuffer(secondStreamId, secondStreamBufferId)}));

  mRenderThread->flush(frameNumber);
}

// Verifies that a task with a frame number higher than the last flushed frame
// number is correctly enqueued and not dropped.
TEST_F(VirtualCameraRenderThreadTest, EnqueueTask_EnqueuesFreshTask) {
  const int flushedFrameNumber = 100;
  const int taskFrameNumber = 101;
  const int streamId = 1;
  const int bufferId = 2;

  mRenderThread->flush(flushedFrameNumber);

  // Enqueueing a task with a frame number higher than the last flushed frame
  // number should not trigger any immediate calls, as the task is queued.
  EXPECT_CALL(*mMockCameraDeviceCallback, notify(testing::_)).Times(0);
  EXPECT_CALL(*mMockCameraDeviceCallback, processCaptureResult(testing::_))
      .Times(0);

  mRenderThread->enqueueTask(std::make_unique<ProcessCaptureRequestTask>(
      taskFrameNumber, std::vector<CaptureRequestBuffer>{
                           CaptureRequestBuffer(streamId, bufferId)}));

  // To verify the task was actually enqueued, we can flush again and check
  // that the error callbacks are now invoked.
  testing::Mock::VerifyAndClearExpectations(mMockCameraDeviceCallback.get());

  EXPECT_CALL(*mMockCameraDeviceCallback,
              notify(ElementsAre(IsRequestErrorNotifyMsg(taskFrameNumber))))
      .WillOnce(Return(ndk::ScopedAStatus::ok()));
  EXPECT_CALL(
      *mMockCameraDeviceCallback,
      processCaptureResult(ElementsAre(AllOf(
          Field(&CaptureResult::frameNumber, taskFrameNumber),
          Field(&CaptureResult::outputBuffers,
                ElementsAre(IsStreamBufferWithStatus(
                    streamId, bufferId, BufferStatus::ERROR)))))))
      .WillOnce(Return(ndk::ScopedAStatus::ok()));

  mRenderThread->flush(taskFrameNumber);
}

TEST_F(VirtualCameraRenderThreadTest,
       ImagePassthroughHandlerBasicFunctionality) {
  int frameReadyCallbackCount = 0;
  // Create an image passthrough handler directly.
  auto handler = VirtualCameraImagePassthroughHandler::create(
      *mSessionContext, kImageFormat,
      /*frameReadyCallback=*/[&]() { frameReadyCallbackCount++; });

  ASSERT_NE(handler, nullptr);

  // Check basic properties are initialized correctly
  EXPECT_NE(handler->getInputSurface(), nullptr);
  EXPECT_FALSE(handler->isFirstFrameDrawn());
  EXPECT_EQ(handler->getTimestamp(), std::chrono::nanoseconds(0));

  // Test a very short timeout should safely return false.
  EXPECT_FALSE(handler->waitForInputFrame(std::chrono::milliseconds(10)));
  EXPECT_EQ(frameReadyCallbackCount, 0);

  // Test interruptWait safely unblocks the wait-for-frame payload with false
  handler->interruptWait();
  EXPECT_FALSE(handler->waitForInputFrame(std::chrono::milliseconds(10)));
  EXPECT_EQ(frameReadyCallbackCount, 0);

  // Test that manually signaling onFrameAvailable triggers the callback and
  // fulfills the promise with true, which propagates to waitForInputFrame
  handler->onFrameAvailable();
  EXPECT_EQ(frameReadyCallbackCount, 1);
  EXPECT_TRUE(handler->waitForInputFrame(std::chrono::milliseconds(10)));
}

TEST_F(VirtualCameraRenderThreadTest, findActualPayloadSizeWithHeicFooter) {
  const int32_t totalSize = 1024;
  const int32_t expectedPayloadSize = 750;
  std::vector<uint8_t> buffer(totalSize, 0);

  // Valid HEIC CameraBlob footer (0x00FE).
  CameraBlob blob{.blobId = static_cast<CameraBlobId>(0x00FE),
                  .blobSizeBytes = expectedPayloadSize};
  memcpy(buffer.data() + totalSize - sizeof(CameraBlob), &blob,
         sizeof(CameraBlob));

  EXPECT_EQ(findActualPayloadSize(buffer.data(), totalSize, Format::HEIC),
            expectedPayloadSize);
}

TEST_F(VirtualCameraRenderThreadTest,
       findActualPayloadSizeMissingFooterReturnsFullSize) {
  const int32_t totalSize = 1024;
  std::vector<uint8_t> buffer(totalSize, 0xCC);

  // No footer present.
  EXPECT_EQ(findActualPayloadSize(buffer.data(), totalSize, Format::HEIC),
            totalSize);
}

}  // namespace
}  // namespace virtualcamera
}  // namespace companion
}  // namespace android
