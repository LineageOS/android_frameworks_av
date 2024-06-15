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

#include "VirtualCameraRenderThread.h"
#include "VirtualCameraSessionContext.h"
#include "aidl/android/hardware/camera/common/CameraDeviceStatus.h"
#include "aidl/android/hardware/camera/common/TorchModeStatus.h"
#include "aidl/android/hardware/camera/device/BnCameraDeviceCallback.h"
#include "aidl/android/hardware/camera/device/BufferRequest.h"
#include "aidl/android/hardware/camera/device/BufferRequestStatus.h"
#include "aidl/android/hardware/camera/device/BufferStatus.h"
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
namespace {

using ::aidl::android::hardware::camera::common::CameraDeviceStatus;
using ::aidl::android::hardware::camera::common::TorchModeStatus;
using ::aidl::android::hardware::camera::device::BnCameraDeviceCallback;
using ::aidl::android::hardware::camera::device::BufferRequest;
using ::aidl::android::hardware::camera::device::BufferRequestStatus;
using ::aidl::android::hardware::camera::device::BufferStatus;
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
    mSessionContext = std::make_unique<VirtualCameraSessionContext>();
    mMockCameraDeviceCallback =
        ndk::SharedRefBase::make<MockCameraDeviceCallback>();
    mRenderThread = std::make_unique<VirtualCameraRenderThread>(
        *mSessionContext, kInputResolution,
        /*reportedSensorSize*/ kInputResolution, mMockCameraDeviceCallback);
  }

 protected:
  std::unique_ptr<VirtualCameraSessionContext> mSessionContext;
  std::unique_ptr<VirtualCameraRenderThread> mRenderThread;
  std::shared_ptr<MockCameraDeviceCallback> mMockCameraDeviceCallback;
};

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

  mRenderThread->flush();
}

}  // namespace
}  // namespace virtualcamera
}  // namespace companion
}  // namespace android
