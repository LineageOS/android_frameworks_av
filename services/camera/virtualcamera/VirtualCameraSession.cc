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
#define LOG_TAG "VirtualCameraSession"
#include "VirtualCameraSession.h"

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <tuple>
#include <unordered_set>
#include <utility>
#include <vector>

#include "CameraMetadata.h"
#include "EGL/egl.h"
#include "VirtualCameraDevice.h"
#include "VirtualCameraRenderThread.h"
#include "VirtualCameraStream.h"
#include "aidl/android/hardware/camera/common/Status.h"
#include "aidl/android/hardware/camera/device/BufferCache.h"
#include "aidl/android/hardware/camera/device/BufferStatus.h"
#include "aidl/android/hardware/camera/device/CaptureRequest.h"
#include "aidl/android/hardware/camera/device/HalStream.h"
#include "aidl/android/hardware/camera/device/NotifyMsg.h"
#include "aidl/android/hardware/camera/device/ShutterMsg.h"
#include "aidl/android/hardware/camera/device/StreamBuffer.h"
#include "aidl/android/hardware/camera/device/StreamConfiguration.h"
#include "aidl/android/hardware/camera/device/StreamRotation.h"
#include "aidl/android/hardware/graphics/common/BufferUsage.h"
#include "aidl/android/hardware/graphics/common/PixelFormat.h"
#include "android/hardware_buffer.h"
#include "android/native_window_aidl.h"
#include "fmq/AidlMessageQueue.h"
#include "system/camera_metadata.h"
#include "ui/GraphicBuffer.h"
#include "util/EglDisplayContext.h"
#include "util/EglFramebuffer.h"
#include "util/EglProgram.h"
#include "util/JpegUtil.h"
#include "util/MetadataBuilder.h"
#include "util/TestPatternHelper.h"
#include "util/Util.h"

namespace android {
namespace companion {
namespace virtualcamera {

using ::aidl::android::companion::virtualcamera::Format;
using ::aidl::android::companion::virtualcamera::IVirtualCameraCallback;
using ::aidl::android::hardware::camera::common::Status;
using ::aidl::android::hardware::camera::device::BufferCache;
using ::aidl::android::hardware::camera::device::CameraMetadata;
using ::aidl::android::hardware::camera::device::CameraOfflineSessionInfo;
using ::aidl::android::hardware::camera::device::CaptureRequest;
using ::aidl::android::hardware::camera::device::HalStream;
using ::aidl::android::hardware::camera::device::ICameraDeviceCallback;
using ::aidl::android::hardware::camera::device::ICameraOfflineSession;
using ::aidl::android::hardware::camera::device::RequestTemplate;
using ::aidl::android::hardware::camera::device::Stream;
using ::aidl::android::hardware::camera::device::StreamBuffer;
using ::aidl::android::hardware::camera::device::StreamConfiguration;
using ::aidl::android::hardware::camera::device::StreamRotation;
using ::aidl::android::hardware::common::fmq::MQDescriptor;
using ::aidl::android::hardware::common::fmq::SynchronizedReadWrite;
using ::aidl::android::hardware::graphics::common::BufferUsage;
using ::aidl::android::hardware::graphics::common::PixelFormat;
using ::android::base::unique_fd;

namespace {

using metadata_ptr =
    std::unique_ptr<camera_metadata_t, void (*)(camera_metadata_t*)>;

using namespace std::chrono_literals;

// Size of request/result metadata fast message queue.
// Setting to 0 to always disables FMQ.
static constexpr size_t kMetadataMsgQueueSize = 0;

// Maximum number of buffers to use per single stream.
static constexpr size_t kMaxStreamBuffers = 2;

CameraMetadata createDefaultRequestSettings(RequestTemplate type) {
  hardware::camera::common::V1_0::helper::CameraMetadata metadataHelper;

  camera_metadata_enum_android_control_capture_intent_t intent =
      ANDROID_CONTROL_CAPTURE_INTENT_PREVIEW;
  switch (type) {
    case RequestTemplate::PREVIEW:
      intent = ANDROID_CONTROL_CAPTURE_INTENT_PREVIEW;
      break;
    case RequestTemplate::STILL_CAPTURE:
      intent = ANDROID_CONTROL_CAPTURE_INTENT_STILL_CAPTURE;
      break;
    case RequestTemplate::VIDEO_RECORD:
      intent = ANDROID_CONTROL_CAPTURE_INTENT_VIDEO_RECORD;
      break;
    case RequestTemplate::VIDEO_SNAPSHOT:
      intent = ANDROID_CONTROL_CAPTURE_INTENT_VIDEO_SNAPSHOT;
      break;
    default:
      // Leave default.
      break;
  }

  auto metadata = MetadataBuilder().setControlCaptureIntent(intent).build();
  return (metadata != nullptr) ? std::move(*metadata) : CameraMetadata();
}

HalStream getHalStream(const Stream& stream) {
  HalStream halStream;
  halStream.id = stream.id;
  halStream.physicalCameraId = stream.physicalCameraId;
  halStream.maxBuffers = kMaxStreamBuffers;

  if (stream.format == PixelFormat::IMPLEMENTATION_DEFINED) {
    // If format is implementation defined we need it to override
    // it with actual format.
    // TODO(b/301023410) Override with the format based on the
    // camera configuration, once we support more formats.
    halStream.overrideFormat = PixelFormat::YCBCR_420_888;
  } else {
    halStream.overrideFormat = stream.format;
  }
  halStream.overrideDataSpace = stream.dataSpace;

  halStream.producerUsage = BufferUsage::GPU_RENDER_TARGET;
  halStream.supportOffline = false;
  return halStream;
}

}  // namespace

VirtualCameraSession::VirtualCameraSession(
    VirtualCameraDevice& cameraDevice,
    std::shared_ptr<ICameraDeviceCallback> cameraDeviceCallback,
    std::shared_ptr<IVirtualCameraCallback> virtualCameraClientCallback)
    : mCameraDevice(cameraDevice),
      mCameraDeviceCallback(cameraDeviceCallback),
      mVirtualCameraClientCallback(virtualCameraClientCallback) {
  mRequestMetadataQueue = std::make_unique<RequestMetadataQueue>(
      kMetadataMsgQueueSize, false /* non blocking */);
  if (!mRequestMetadataQueue->isValid()) {
    ALOGE("%s: invalid request fmq", __func__);
  }

  mResultMetadataQueue = std::make_shared<ResultMetadataQueue>(
      kMetadataMsgQueueSize, false /* non blocking */);
  if (!mResultMetadataQueue->isValid()) {
    ALOGE("%s: invalid result fmq", __func__);
  }
}

ndk::ScopedAStatus VirtualCameraSession::close() {
  ALOGV("%s", __func__);

  if (mVirtualCameraClientCallback != nullptr) {
    mVirtualCameraClientCallback->onStreamClosed(/*streamId=*/0);
  }

  {
    std::lock_guard<std::mutex> lock(mLock);
    if (mRenderThread != nullptr) {
      mRenderThread->stop();
      mRenderThread = nullptr;
    }
  }

  mSessionContext.closeAllStreams();
  return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus VirtualCameraSession::configureStreams(
    const StreamConfiguration& in_requestedConfiguration,
    std::vector<HalStream>* _aidl_return) {
  ALOGV("%s: requestedConfiguration: %s", __func__,
        in_requestedConfiguration.toString().c_str());

  if (_aidl_return == nullptr) {
    return cameraStatus(Status::ILLEGAL_ARGUMENT);
  }

  mSessionContext.removeStreamsNotInStreamConfiguration(
      in_requestedConfiguration);

  auto& streams = in_requestedConfiguration.streams;
  auto& halStreams = *_aidl_return;
  halStreams.clear();
  halStreams.resize(in_requestedConfiguration.streams.size());

  sp<Surface> inputSurface = nullptr;
  int inputWidth;
  int inputHeight;

  if (!mCameraDevice.isStreamCombinationSupported(in_requestedConfiguration)) {
    ALOGE("%s: Requested stream configuration is not supported", __func__);
    return cameraStatus(Status::ILLEGAL_ARGUMENT);
  }

  {
    std::lock_guard<std::mutex> lock(mLock);
    for (int i = 0; i < in_requestedConfiguration.streams.size(); ++i) {
      halStreams[i] = getHalStream(streams[i]);
      if (mSessionContext.initializeStream(streams[i])) {
        ALOGV("Configured new stream: %s", streams[i].toString().c_str());
      }
    }

    inputWidth = streams[0].width;
    inputHeight = streams[0].height;
    if (mRenderThread == nullptr) {
      // If there's no client callback, start camera in test mode.
      const bool testMode = mVirtualCameraClientCallback == nullptr;
      mRenderThread = std::make_unique<VirtualCameraRenderThread>(
          mSessionContext, inputWidth, inputHeight, mCameraDeviceCallback,
          testMode);
      mRenderThread->start();
      inputSurface = mRenderThread->getInputSurface();
    }
  }

  if (mVirtualCameraClientCallback != nullptr && inputSurface != nullptr) {
    // TODO(b/301023410) Pass streamId based on client input stream id once
    // support for multiple input streams is implemented. For now we always
    // create single texture.
    mVirtualCameraClientCallback->onStreamConfigured(
        /*streamId=*/0, aidl::android::view::Surface(inputSurface.get()),
        inputWidth, inputHeight, Format::YUV_420_888);
  }

  mFirstRequest.store(true);
  return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus VirtualCameraSession::constructDefaultRequestSettings(
    RequestTemplate in_type, CameraMetadata* _aidl_return) {
  ALOGV("%s: type %d", __func__, static_cast<int32_t>(in_type));

  switch (in_type) {
    case RequestTemplate::PREVIEW:
    case RequestTemplate::STILL_CAPTURE:
    case RequestTemplate::VIDEO_RECORD: {
      *_aidl_return = createDefaultRequestSettings(in_type);
      return ndk::ScopedAStatus::ok();
    }
    case RequestTemplate::VIDEO_SNAPSHOT:
    case RequestTemplate::MANUAL:
    case RequestTemplate::ZERO_SHUTTER_LAG:
      // Don't support VIDEO_SNAPSHOT, MANUAL, ZSL templates
      return ndk::ScopedAStatus::fromServiceSpecificError(
          static_cast<int32_t>(Status::ILLEGAL_ARGUMENT));
      ;
    default:
      ALOGE("%s: unknown request template type %d", __FUNCTION__,
            static_cast<int>(in_type));
      return ndk::ScopedAStatus::fromServiceSpecificError(
          static_cast<int32_t>(Status::ILLEGAL_ARGUMENT));
      ;
  }
}

ndk::ScopedAStatus VirtualCameraSession::flush() {
  ALOGV("%s", __func__);
  std::lock_guard<std::mutex> lock(mLock);
  if (mRenderThread != nullptr) {
    mRenderThread->flush();
  }
  return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus VirtualCameraSession::getCaptureRequestMetadataQueue(
    MQDescriptor<int8_t, SynchronizedReadWrite>* _aidl_return) {
  ALOGV("%s", __func__);
  *_aidl_return = mRequestMetadataQueue->dupeDesc();
  return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus VirtualCameraSession::getCaptureResultMetadataQueue(
    MQDescriptor<int8_t, SynchronizedReadWrite>* _aidl_return) {
  ALOGV("%s", __func__);
  *_aidl_return = mResultMetadataQueue->dupeDesc();
  return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus VirtualCameraSession::isReconfigurationRequired(
    const CameraMetadata& in_oldSessionParams,
    const CameraMetadata& in_newSessionParams, bool* _aidl_return) {
  ALOGV("%s: oldSessionParams: %s newSessionParams: %s", __func__,
        in_newSessionParams.toString().c_str(),
        in_oldSessionParams.toString().c_str());

  if (_aidl_return == nullptr) {
    return ndk::ScopedAStatus::fromServiceSpecificError(
        static_cast<int32_t>(Status::ILLEGAL_ARGUMENT));
  }

  *_aidl_return = true;
  return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus VirtualCameraSession::processCaptureRequest(
    const std::vector<CaptureRequest>& in_requests,
    const std::vector<BufferCache>& in_cachesToRemove, int32_t* _aidl_return) {
  ALOGV("%s", __func__);

  if (!in_cachesToRemove.empty()) {
    mSessionContext.removeBufferCaches(in_cachesToRemove);
  }

  for (const auto& captureRequest : in_requests) {
    auto status = processCaptureRequest(captureRequest);
    if (!status.isOk()) {
      return status;
    }
  }
  *_aidl_return = in_requests.size();
  return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus VirtualCameraSession::signalStreamFlush(
    const std::vector<int32_t>& in_streamIds, int32_t in_streamConfigCounter) {
  ALOGV("%s", __func__);

  (void)in_streamIds;
  (void)in_streamConfigCounter;
  return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus VirtualCameraSession::switchToOffline(
    const std::vector<int32_t>& in_streamsToKeep,
    CameraOfflineSessionInfo* out_offlineSessionInfo,
    std::shared_ptr<ICameraOfflineSession>* _aidl_return) {
  ALOGV("%s", __func__);

  (void)in_streamsToKeep;
  (void)out_offlineSessionInfo;

  if (_aidl_return == nullptr) {
    return ndk::ScopedAStatus::fromServiceSpecificError(
        static_cast<int32_t>(Status::ILLEGAL_ARGUMENT));
  }

  *_aidl_return = nullptr;
  return cameraStatus(Status::OPERATION_NOT_SUPPORTED);
}

ndk::ScopedAStatus VirtualCameraSession::repeatingRequestEnd(
    int32_t in_frameNumber, const std::vector<int32_t>& in_streamIds) {
  ALOGV("%s", __func__);
  (void)in_frameNumber;
  (void)in_streamIds;
  return ndk::ScopedAStatus::ok();
}

std::set<int> VirtualCameraSession::getStreamIds() const {
  return mSessionContext.getStreamIds();
}

ndk::ScopedAStatus VirtualCameraSession::processCaptureRequest(
    const CaptureRequest& request) {
  ALOGD("%s: request: %s", __func__, request.toString().c_str());

  if (mFirstRequest.exchange(false) && request.settings.metadata.empty()) {
    return cameraStatus(Status::ILLEGAL_ARGUMENT);
  }

  std::shared_ptr<ICameraDeviceCallback> cameraCallback = nullptr;
  {
    std::lock_guard<std::mutex> lock(mLock);
    cameraCallback = mCameraDeviceCallback;
  }

  if (cameraCallback == nullptr) {
    ALOGE(
        "%s: processCaptureRequest called, but there's no camera callback "
        "configured",
        __func__);
    return cameraStatus(Status::INTERNAL_ERROR);
  }

  if (!mSessionContext.importBuffersFromCaptureRequest(request)) {
    ALOGE("Failed to import buffers from capture request.");
    return cameraStatus(Status::INTERNAL_ERROR);
  }

  std::vector<CaptureRequestBuffer> taskBuffers;
  taskBuffers.reserve(request.outputBuffers.size());
  for (const StreamBuffer& streamBuffer : request.outputBuffers) {
    taskBuffers.emplace_back(streamBuffer.streamId, streamBuffer.bufferId,
                             importFence(streamBuffer.acquireFence));
  }

  {
    std::lock_guard<std::mutex> lock(mLock);
    if (mRenderThread == nullptr) {
      ALOGE(
          "%s: processCaptureRequest (frameNumber %d)called before configure "
          "(render thread not initialized)",
          __func__, request.frameNumber);
      return cameraStatus(Status::INTERNAL_ERROR);
    }
    mRenderThread->enqueueTask(std::make_unique<ProcessCaptureRequestTask>(
        request.frameNumber, taskBuffers));
  }

  if (mVirtualCameraClientCallback != nullptr) {
    auto status = mVirtualCameraClientCallback->onProcessCaptureRequest(
        /*streamId=*/0, request.frameNumber);
    if (!status.isOk()) {
      ALOGE(
          "Failed to invoke onProcessCaptureRequest client callback for frame "
          "%d",
          request.frameNumber);
    }
  }

  return ndk::ScopedAStatus::ok();
}

}  // namespace virtualcamera
}  // namespace companion
}  // namespace android
