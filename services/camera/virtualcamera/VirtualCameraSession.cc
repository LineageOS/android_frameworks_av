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

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <numeric>
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
#include "aidl/android/companion/virtualcamera/SupportedStreamConfiguration.h"
#include "aidl/android/hardware/camera/common/Status.h"
#include "aidl/android/hardware/camera/device/BufferCache.h"
#include "aidl/android/hardware/camera/device/BufferStatus.h"
#include "aidl/android/hardware/camera/device/CameraMetadata.h"
#include "aidl/android/hardware/camera/device/CaptureRequest.h"
#include "aidl/android/hardware/camera/device/HalStream.h"
#include "aidl/android/hardware/camera/device/NotifyMsg.h"
#include "aidl/android/hardware/camera/device/RequestTemplate.h"
#include "aidl/android/hardware/camera/device/ShutterMsg.h"
#include "aidl/android/hardware/camera/device/Stream.h"
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
#include "util/MetadataUtil.h"
#include "util/TestPatternHelper.h"
#include "util/Util.h"

namespace android {
namespace companion {
namespace virtualcamera {

using ::aidl::android::companion::virtualcamera::Format;
using ::aidl::android::companion::virtualcamera::IVirtualCameraCallback;
using ::aidl::android::companion::virtualcamera::SupportedStreamConfiguration;
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
constexpr size_t kMetadataMsgQueueSize = 0;

// Maximum number of buffers to use per single stream.
constexpr size_t kMaxStreamBuffers = 2;

// Thumbnail size (0,0) correspods to disabling thumbnail.
const Resolution kDefaultJpegThumbnailSize(0, 0);

camera_metadata_enum_android_control_capture_intent_t requestTemplateToIntent(
    const RequestTemplate type) {
  switch (type) {
    case RequestTemplate::PREVIEW:
      return ANDROID_CONTROL_CAPTURE_INTENT_PREVIEW;
    case RequestTemplate::STILL_CAPTURE:
      return ANDROID_CONTROL_CAPTURE_INTENT_STILL_CAPTURE;
    case RequestTemplate::VIDEO_RECORD:
      return ANDROID_CONTROL_CAPTURE_INTENT_VIDEO_RECORD;
    case RequestTemplate::VIDEO_SNAPSHOT:
      return ANDROID_CONTROL_CAPTURE_INTENT_VIDEO_SNAPSHOT;
    default:
      // Return PREVIEW by default
      return ANDROID_CONTROL_CAPTURE_INTENT_PREVIEW;
  }
}

int getMaxFps(const std::vector<SupportedStreamConfiguration>& configs) {
  return std::transform_reduce(
      configs.begin(), configs.end(), 0,
      [](const int a, const int b) { return std::max(a, b); },
      [](const SupportedStreamConfiguration& config) { return config.maxFps; });
}

CameraMetadata createDefaultRequestSettings(
    const RequestTemplate type,
    const std::vector<SupportedStreamConfiguration>& inputConfigs) {
  int maxFps = getMaxFps(inputConfigs);
  auto metadata =
      MetadataBuilder()
          .setAberrationCorrectionMode(
              ANDROID_COLOR_CORRECTION_ABERRATION_MODE_OFF)
          .setControlCaptureIntent(requestTemplateToIntent(type))
          .setControlMode(ANDROID_CONTROL_MODE_AUTO)
          .setControlAeMode(ANDROID_CONTROL_AE_MODE_ON)
          .setControlAeExposureCompensation(0)
          .setControlAeTargetFpsRange(maxFps, maxFps)
          .setControlAeAntibandingMode(ANDROID_CONTROL_AE_ANTIBANDING_MODE_AUTO)
          .setControlAePrecaptureTrigger(
              ANDROID_CONTROL_AE_PRECAPTURE_TRIGGER_IDLE)
          .setControlAfTrigger(ANDROID_CONTROL_AF_TRIGGER_IDLE)
          .setControlAfMode(ANDROID_CONTROL_AF_MODE_OFF)
          .setControlAwbMode(ANDROID_CONTROL_AWB_MODE_AUTO)
          .setControlEffectMode(ANDROID_CONTROL_EFFECT_MODE_OFF)
          .setFaceDetectMode(ANDROID_STATISTICS_FACE_DETECT_MODE_OFF)
          .setFlashMode(ANDROID_FLASH_MODE_OFF)
          .setFlashState(ANDROID_FLASH_STATE_UNAVAILABLE)
          .setJpegQuality(VirtualCameraDevice::kDefaultJpegQuality)
          .setJpegThumbnailQuality(VirtualCameraDevice::kDefaultJpegQuality)
          .setJpegThumbnailSize(0, 0)
          .setNoiseReductionMode(ANDROID_NOISE_REDUCTION_MODE_OFF)
          .build();
  if (metadata == nullptr) {
    ALOGE("%s: Failed to construct metadata for default request type %s",
          __func__, toString(type).c_str());
    return CameraMetadata();
  } else {
    ALOGV("%s: Successfully created metadata for request type %s", __func__,
          toString(type).c_str());
  }
  return *metadata;
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

Stream getHighestResolutionStream(const std::vector<Stream>& streams) {
  return *(std::max_element(streams.begin(), streams.end(),
                            [](const Stream& a, const Stream& b) {
                              return a.width * a.height < b.width * b.height;
                            }));
}

Resolution resolutionFromStream(const Stream& stream) {
  return Resolution(stream.width, stream.height);
}

Resolution resolutionFromInputConfig(
    const SupportedStreamConfiguration& inputConfig) {
  return Resolution(inputConfig.width, inputConfig.height);
}

std::optional<SupportedStreamConfiguration> pickInputConfigurationForStreams(
    const std::vector<Stream>& requestedStreams,
    const std::vector<SupportedStreamConfiguration>& supportedInputConfigs) {
  Stream maxResolutionStream = getHighestResolutionStream(requestedStreams);
  Resolution maxResolution = resolutionFromStream(maxResolutionStream);

  // Find best fitting stream to satisfy all requested streams:
  // Best fitting => same or higher resolution as input with lowest pixel count
  // difference and same aspect ratio.
  auto isBetterInputConfig = [maxResolution](
                                 const SupportedStreamConfiguration& configA,
                                 const SupportedStreamConfiguration& configB) {
    int maxResPixelCount = maxResolution.width * maxResolution.height;
    int pixelCountDiffA =
        std::abs((configA.width * configA.height) - maxResPixelCount);
    int pixelCountDiffB =
        std::abs((configB.width * configB.height) - maxResPixelCount);

    return pixelCountDiffA < pixelCountDiffB;
  };

  std::optional<SupportedStreamConfiguration> bestConfig;
  for (const SupportedStreamConfiguration& inputConfig : supportedInputConfigs) {
    Resolution inputConfigResolution = resolutionFromInputConfig(inputConfig);
    if (inputConfigResolution < maxResolution ||
        !isApproximatellySameAspectRatio(inputConfigResolution, maxResolution)) {
      // We don't want to upscale from lower resolution, or use different aspect
      // ratio, skip.
      continue;
    }

    if (!bestConfig.has_value() ||
        isBetterInputConfig(inputConfig, bestConfig.value())) {
      bestConfig = inputConfig;
    }
  }

  return bestConfig;
}

RequestSettings createSettingsFromMetadata(const CameraMetadata& metadata) {
  return RequestSettings{
      .jpegQuality = getJpegQuality(metadata).value_or(
          VirtualCameraDevice::kDefaultJpegQuality),
      .thumbnailResolution =
          getJpegThumbnailSize(metadata).value_or(Resolution(0, 0)),
      .thumbnailJpegQuality = getJpegThumbnailQuality(metadata).value_or(
          VirtualCameraDevice::kDefaultJpegQuality)};
}

}  // namespace

VirtualCameraSession::VirtualCameraSession(
    std::shared_ptr<VirtualCameraDevice> cameraDevice,
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

  std::shared_ptr<VirtualCameraDevice> virtualCamera = mCameraDevice.lock();
  if (virtualCamera == nullptr) {
    ALOGW("%s: configure called on already unregistered camera", __func__);
    return cameraStatus(Status::CAMERA_DISCONNECTED);
  }

  mSessionContext.removeStreamsNotInStreamConfiguration(
      in_requestedConfiguration);

  auto& streams = in_requestedConfiguration.streams;
  auto& halStreams = *_aidl_return;
  halStreams.clear();
  halStreams.resize(in_requestedConfiguration.streams.size());

  if (!virtualCamera->isStreamCombinationSupported(in_requestedConfiguration)) {
    ALOGE("%s: Requested stream configuration is not supported", __func__);
    return cameraStatus(Status::ILLEGAL_ARGUMENT);
  }

  sp<Surface> inputSurface = nullptr;
  std::optional<SupportedStreamConfiguration> inputConfig;
  {
    std::lock_guard<std::mutex> lock(mLock);
    for (int i = 0; i < in_requestedConfiguration.streams.size(); ++i) {
      halStreams[i] = getHalStream(streams[i]);
      if (mSessionContext.initializeStream(streams[i])) {
        ALOGV("Configured new stream: %s", streams[i].toString().c_str());
      }
    }

    inputConfig = pickInputConfigurationForStreams(
        streams, virtualCamera->getInputConfigs());
    if (!inputConfig.has_value()) {
      ALOGE(
          "%s: Failed to pick any input configuration for stream configuration "
          "request: %s",
          __func__, in_requestedConfiguration.toString().c_str());
      return cameraStatus(Status::ILLEGAL_ARGUMENT);
    }
    if (mRenderThread == nullptr) {
      // If there's no client callback, start camera in test mode.
      const bool testMode = mVirtualCameraClientCallback == nullptr;
      mRenderThread = std::make_unique<VirtualCameraRenderThread>(
          mSessionContext, resolutionFromInputConfig(*inputConfig),
          virtualCamera->getMaxInputResolution(), mCameraDeviceCallback,
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
        inputConfig->width, inputConfig->height, inputConfig->pixelFormat);
  }

  return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus VirtualCameraSession::constructDefaultRequestSettings(
    RequestTemplate in_type, CameraMetadata* _aidl_return) {
  ALOGV("%s: type %d", __func__, static_cast<int32_t>(in_type));

  std::shared_ptr<VirtualCameraDevice> camera = mCameraDevice.lock();
  if (camera == nullptr) {
    ALOGW(
        "%s: constructDefaultRequestSettings called on already unregistered "
        "camera",
        __func__);
    return cameraStatus(Status::CAMERA_DISCONNECTED);
  }

  switch (in_type) {
    case RequestTemplate::PREVIEW:
    case RequestTemplate::STILL_CAPTURE:
    case RequestTemplate::VIDEO_RECORD:
    case RequestTemplate::VIDEO_SNAPSHOT: {
      *_aidl_return =
          createDefaultRequestSettings(in_type, camera->getInputConfigs());
      return ndk::ScopedAStatus::ok();
    }
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

  std::shared_ptr<ICameraDeviceCallback> cameraCallback = nullptr;
  RequestSettings requestSettings;
  {
    std::lock_guard<std::mutex> lock(mLock);

    // If metadata it empty, last received metadata applies, if  it's non-empty
    // update it.
    if (!request.settings.metadata.empty()) {
      mCurrentRequestMetadata = request.settings;
    }

    // We don't have any metadata for this request - this means we received none
    // in first request, this is an error state.
    if (mCurrentRequestMetadata.metadata.empty()) {
      return cameraStatus(Status::ILLEGAL_ARGUMENT);
    }

    requestSettings = createSettingsFromMetadata(mCurrentRequestMetadata);

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
        request.frameNumber, taskBuffers, requestSettings));
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
