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

#include <android_companion_virtualdevice_flags.h>

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <numeric>
#include <optional>
#include <utility>
#include <vector>

#include "VirtualCameraCaptureResultConsumer.h"
#include "VirtualCameraDevice.h"
#include "VirtualCameraRenderThread.h"
#include "aidl/android/companion/virtualcamera/ICaptureResultConsumer.h"
#include "aidl/android/companion/virtualcamera/SupportedStreamConfiguration.h"
#include "aidl/android/companion/virtualcamera/VirtualCameraMetadata.h"
#include "aidl/android/hardware/camera/common/Status.h"
#include "aidl/android/hardware/camera/device/BufferCache.h"
#include "aidl/android/hardware/camera/device/CameraMetadata.h"
#include "aidl/android/hardware/camera/device/CaptureRequest.h"
#include "aidl/android/hardware/camera/device/HalStream.h"
#include "aidl/android/hardware/camera/device/RequestTemplate.h"
#include "aidl/android/hardware/camera/device/Stream.h"
#include "aidl/android/hardware/camera/device/StreamBuffer.h"
#include "aidl/android/hardware/camera/device/StreamConfiguration.h"
#include "aidl/android/hardware/graphics/common/BufferUsage.h"
#include "aidl/android/hardware/graphics/common/PixelFormat.h"
#include "android/native_window_aidl.h"
#include "fmq/AidlMessageQueue.h"
#include "system/camera_metadata.h"
#include "ui/GraphicBuffer.h"
#include "util/AidlUtil.h"
#include "util/MetadataUtil.h"
#include "util/Util.h"

namespace android {
namespace companion {
namespace virtualcamera {

using ::aidl::android::companion::virtualcamera::IVirtualCameraCallback;
using ::aidl::android::companion::virtualcamera::SupportedStreamConfiguration;
using ::aidl::android::companion::virtualcamera::VirtualCameraMetadata;
using ::aidl::android::hardware::camera::common::Status;
using ::aidl::android::hardware::camera::device::BufferCache;
using ::aidl::android::hardware::camera::device::CameraMetadata;
using ::aidl::android::hardware::camera::device::CameraOfflineSessionInfo;
using ::aidl::android::hardware::camera::device::CaptureRequest;
using ::aidl::android::hardware::camera::device::ErrorCode;
using ::aidl::android::hardware::camera::device::ErrorMsg;
using ::aidl::android::hardware::camera::device::HalStream;
using ::aidl::android::hardware::camera::device::ICameraDeviceCallback;
using ::aidl::android::hardware::camera::device::ICameraOfflineSession;
using ::aidl::android::hardware::camera::device::NotifyMsg;
using ::aidl::android::hardware::camera::device::RequestTemplate;
using ::aidl::android::hardware::camera::device::Stream;
using ::aidl::android::hardware::camera::device::StreamBuffer;
using ::aidl::android::hardware::camera::device::StreamConfiguration;
using ::aidl::android::hardware::common::fmq::MQDescriptor;
using ::aidl::android::hardware::common::fmq::SynchronizedReadWrite;
using ::aidl::android::hardware::graphics::common::BufferUsage;
using ::aidl::android::hardware::graphics::common::PixelFormat;
using ::android::base::unique_fd;

namespace {

using namespace std::chrono_literals;
namespace flags = ::android::companion::virtualdevice::flags;

// Size of request/result metadata fast message queue.
// Setting to 0 to always disables FMQ.
constexpr size_t kMetadataMsgQueueSize = 0;

// Maximum number of buffers to use per single stream.
constexpr size_t kMaxStreamBuffers = 2;

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
          .setControlAeTargetFpsRange(FpsRange{maxFps, maxFps})
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

  halStream.producerUsage = static_cast<BufferUsage>(
      static_cast<int64_t>(stream.usage) |
      static_cast<int64_t>(BufferUsage::CAMERA_OUTPUT) |
      static_cast<int64_t>(BufferUsage::GPU_RENDER_TARGET) |
      static_cast<int64_t>(BufferUsage::CPU_WRITE_OFTEN));

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

// Search stream configurations from Camera2 and Virtual Camera Owner for a
// matching pair that enables a direct blob transfer.
//
// Return configuration if a direct blob transfer is possible. Otherwise return
// nullopt if no direct blob transfer is possible
std::optional<SupportedStreamConfiguration> getExactMatchingBlobStreamConfiguration(
    const std::vector<Stream>& requestedStreams,
    const std::vector<SupportedStreamConfiguration>& supportedInputConfigs) {
  if (requestedStreams.empty()) {
    ALOGE("%s: requested streams is empty!", __func__);
    return std::nullopt;
  }
  if (supportedInputConfigs.empty()) {
    ALOGE("%s: supported input configs is empty!", __func__);
    return std::nullopt;
  }
  if (!flags::virtual_camera_direct_blob_transfer()) {
    return std::nullopt;
  }

  // Multiple output streams are only possible with direct blob transfer if the
  // ImageFormat and resolutions are the same
  const Stream& firstStream = requestedStreams.front();
  if (!isBlobStreamConfig(firstStream)) {
    return std::nullopt;
  }

  bool heterogeneousRequestedStreams = std::any_of(
      requestedStreams.begin() + 1, requestedStreams.end(),
      [&firstStream](const Stream& s) {
        return !areMatchingBlobTypes(firstStream, s) ||
               firstStream.width != s.width || firstStream.height != s.height;
      });

  if (heterogeneousRequestedStreams) {
    return std::nullopt;
  }

  auto availableBlobInputStreamConfig = std::find_if(
      supportedInputConfigs.begin(), supportedInputConfigs.end(),
      [&firstStream](const SupportedStreamConfiguration& c) {
        return areMatchingBlobTypes(firstStream, c) &&
               firstStream.width == c.width && firstStream.height == c.height;
      });

  if (availableBlobInputStreamConfig == supportedInputConfigs.end()) {
    return std::nullopt;
  }

  return *availableBlobInputStreamConfig;
}

std::optional<SupportedStreamConfiguration> pickInputConfigurationForStreams(
    const std::vector<Stream>& requestedStreams,
    const std::vector<SupportedStreamConfiguration>& supportedInputConfigs) {
  if (requestedStreams.empty()) {
    ALOGE("%s: requested streams is empty!", __func__);
    return std::nullopt;
  }
  if (supportedInputConfigs.empty()) {
    ALOGE("%s: supported input configs is empty!", __func__);
    return std::nullopt;
  }

  std::optional<SupportedStreamConfiguration> bestConfig =
      getExactMatchingBlobStreamConfiguration(requestedStreams,
                                              supportedInputConfigs);

  if (bestConfig.has_value()) {
    ALOGI(
        "%s: direct blob transfer available for requested stream config. "
        "Attempting to set up direct transfer...",
        __func__);
    return bestConfig;
  }

  // Filter out BLOB input formats since a direct "passthrough" transfer cannot
  // be established. Past this point, only unencoded inputs can be used, e.g.
  // i420
  std::vector<SupportedStreamConfiguration> nonBlobInputConfigs;
  std::copy_if(supportedInputConfigs.begin(), supportedInputConfigs.end(),
               std::back_inserter(nonBlobInputConfigs),
               [](const SupportedStreamConfiguration& config) {
                 return !isBlobFormat(config.imageFormat);
               });

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

  for (const SupportedStreamConfiguration& inputConfig : nonBlobInputConfigs) {
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
      ALOGV("Current Best Config %s", bestConfig.value().toString().c_str());
    }
  }

  return bestConfig;
}

RequestSettings createSettingsFromMetadata(const CameraMetadata& metadata) {
  return RequestSettings{
      .jpegQuality = getJpegQuality(metadata).value_or(
          VirtualCameraDevice::kDefaultJpegQuality),
      .jpegOrientation = getJpegOrientation(metadata),
      .thumbnailResolution =
          getJpegThumbnailSize(metadata).value_or(Resolution(0, 0)),
      .thumbnailJpegQuality = getJpegThumbnailQuality(metadata).value_or(
          VirtualCameraDevice::kDefaultJpegQuality),
      .fpsRange = getFpsRange(metadata),
      .captureIntent = getCaptureIntent(metadata).value_or(
          ANDROID_CONTROL_CAPTURE_INTENT_PREVIEW),
      .gpsCoordinates = getGpsCoordinates(metadata),
      .aePrecaptureTrigger = getPrecaptureTrigger(metadata)};
}

};  // namespace

VirtualCameraSession::VirtualCameraSession(
    std::shared_ptr<VirtualCameraDevice> cameraDevice,
    std::shared_ptr<ICameraDeviceCallback> cameraDeviceCallback,
    std::shared_ptr<IVirtualCameraCallback> virtualCameraClientCallback)
    : mCameraDevice(cameraDevice),
      mCameraDeviceCallback(cameraDeviceCallback),
      mVirtualCameraClientCallback(virtualCameraClientCallback),
      mSessionContext(cameraDevice->isMultiInputStreamEnabled(),
                      [this]() { onSessionError(); }),
      mCurrentInputStreamId(kInvalidStreamId) {
  mRequestMetadataQueue = std::make_unique<RequestMetadataQueue>(
      kMetadataMsgQueueSize, false /* non blocking */);
  if (!mRequestMetadataQueue->isValid()) {
    ALOGW("%s: invalid request fmq", __func__);
  }

  mResultMetadataQueue = std::make_shared<ResultMetadataQueue>(
      kMetadataMsgQueueSize, false /* non blocking */);
  if (!mResultMetadataQueue->isValid()) {
    ALOGW("%s: invalid result fmq", __func__);
  }

  std::shared_ptr<VirtualCameraDevice> virtualCamera = mCameraDevice.lock();
  if (virtualCamera != nullptr &&
      virtualCamera->isPerFrameCameraMetadataEnabled()) {
    // create a capture result consumer shared reference and set it in the
    // session context.
    mSessionContext.setCaptureResultConsumer(
        ndk::SharedRefBase::make<VirtualCameraCaptureResultConsumer>());
  }
}

ndk::ScopedAStatus VirtualCameraSession::close() {
  ALOGV("%s: isMultiInputStreamEnabled %d", __func__,
        mSessionContext.isMultiInputStreamEnabled());

  if (mSessionContext.isMultiInputStreamEnabled()) {
    std::set<int> staleStream =
        mSessionContext.updateOpenStreams(std::map<int, int>());

    for (int streamId : staleStream) {
      ALOGV(
          "VirtualCameraSession::close: closing input stream for thread id %d",
          streamId);
      if (mVirtualCameraClientCallback != nullptr) {
        mVirtualCameraClientCallback->onStreamClosed(streamId);
      }
    }

    closeUnusedRenderThreads();
  } else {
    std::unique_ptr<VirtualCameraRenderThread> renderThread;
    {
      std::lock_guard<std::mutex> lock(mLock);
      if (mRenderThread != nullptr) {
        mRenderThread->flush();
        // defer the stop of the render thread outside of the lock
        renderThread = std::move(mRenderThread);
        mRenderThread = nullptr;
      }

      if (mVirtualCameraClientCallback != nullptr &&
          mCurrentInputStreamId != kInvalidStreamId) {
        ALOGV("Calling onStreamClosed for %d", mCurrentInputStreamId);
        mVirtualCameraClientCallback->onStreamClosed(mCurrentInputStreamId);
      }
      mCurrentInputStreamId = kInvalidStreamId;
    }

    // stop the render thread outside of the lock
    if (renderThread != nullptr) {
      renderThread->stop();  // this does a blocking join() in destructor
    } else {
      ALOGI("Trying to close a session with no render thread");
    }
  }

  mSessionContext.clearStreams();
  return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus VirtualCameraSession::configureStreams(
    const StreamConfiguration& in_requestedConfiguration,
    std::vector<HalStream>* _aidl_return) {
  if (isInFatalError()) {
    return cameraStatus(Status::INTERNAL_ERROR);
  }
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

  const std::vector<Stream>& streams = in_requestedConfiguration.streams;
  std::vector<HalStream>& halStreams = *_aidl_return;
  halStreams.clear();
  halStreams.resize(in_requestedConfiguration.streams.size());

  if (!virtualCamera->isStreamCombinationSupported(in_requestedConfiguration)) {
    ALOGE(
        "%s: Requested stream configuration is not supported, closing "
        "existing session",
        __func__);
    close();
    return cameraStatus(Status::ILLEGAL_ARGUMENT);
  }

  sp<Surface> inputSurface = nullptr;
  int inputStreamId = -1;
  std::optional<SupportedStreamConfiguration> inputConfig;
  std::unique_ptr<VirtualCameraRenderThread> renderThread;
  {
    std::lock_guard<std::mutex> lock(mLock);
    for (int i = 0; i < in_requestedConfiguration.streams.size(); ++i) {
      halStreams[i] = getHalStream(streams[i]);
      if (mSessionContext.initializeStream(streams[i])) {
        ALOGV("Configured new output stream: %s", streams[i].toString().c_str());
      }
    }
  }

  // Multi Stream configuration
  if (mSessionContext.isMultiInputStreamEnabled()) {
    ALOGV("Multi input streams configuration");
    configureMultiStream(virtualCamera, in_requestedConfiguration, &halStreams);
  } else {
    ALOGV("Single input stream configuration");
    std::lock_guard<std::mutex> lock(mLock);
    inputConfig = pickInputConfigurationForStreams(
        streams, virtualCamera->getInputConfigs());
    if (!inputConfig.has_value()) {
      ALOGE(
          "%s: Failed to pick any input configuration for stream "
          "configuration request: %s",
          __func__, in_requestedConfiguration.toString().c_str());
      return cameraStatus(Status::ILLEGAL_ARGUMENT);
    }

    if (mRenderThread != nullptr) {
      // If there's already a render thread, it means this is not a first
      // configuration call. If the surface has the same resolution and pixel
      // format as the picked config, we don't need to do anything, the current
      // render thread is capable of serving new set of configuration. However
      // if it differs, we need to discard the current surface and
      // reinitialize the render thread.

      Resolution currentInputResolution = mRenderThread->getInputResolution();
      if (currentInputResolution == resolutionFromInputConfig(*inputConfig)) {
        // BLOB types must match (if applicable), otherwise the existing
        // surface cannot be reused and must be regenerated
        if ((isBlobFormat(mRenderThread->getImageFormat()) ||
             isBlobFormat(inputConfig->imageFormat)) &&
            mRenderThread->getImageFormat() != inputConfig->imageFormat) {
          ALOGI(
              "%s: render thread currently configured for BLOB (format=0x%x) "
              "but input configuration has format=0x%x",
              __func__, mRenderThread->getImageFormat(),
              inputConfig->imageFormat);
        } else {
          ALOGI(
              "%s: Newly configured set of streams matches existing client "
              "surface (%dx%d)",
              __func__, currentInputResolution.width,
              currentInputResolution.height);
          return ndk::ScopedAStatus::ok();
        }
      }

      if (mVirtualCameraClientCallback != nullptr) {
        mVirtualCameraClientCallback->onStreamClosed(mCurrentInputStreamId);
      }

      ALOGV(
          "%s: Newly requested output streams are not suitable for "
          "pre-existing surface (%dx%d), creating new surface (%dx%d)",
          __func__, currentInputResolution.width, currentInputResolution.height,
          inputConfig->width, inputConfig->height);

      mRenderThread->flush();
      // defer the stop of the render thread outside of the lock
      renderThread = std::move(mRenderThread);
      mRenderThread = nullptr;
    }

    mRenderThread = std::make_unique<VirtualCameraRenderThread>(
        mSessionContext, inputConfig->index, inputConfig->imageFormat,
        resolutionFromInputConfig(*inputConfig),
        virtualCamera->getMaxInputResolution(), mCameraDeviceCallback);

    if (!mRenderThread->start()) {
      ALOGE("%s: failed to start render thread", __func__);
      return cameraStatus(Status::ILLEGAL_ARGUMENT);
    }

    inputSurface = mRenderThread->getInputSurface();
    inputStreamId = mCurrentInputStreamId =
        flags::virtual_camera_stable_stream_id() || true  // b/475805468
            ? inputConfig->index
            : virtualCamera->allocateInputStreamId();
  }  // end single stream config

  // The onConfigureSession is oneway async, just informs the VD owner of
  // the session params
  if (mVirtualCameraClientCallback != nullptr) {
    VirtualCameraMetadata sessionParamsMetadata;
    status_t ret = convertDeviceToVirtualCameraMetadata(
        in_requestedConfiguration.sessionParams, sessionParamsMetadata);
    if (ret != OK) {
      ALOGE("Failed to convert device to virtual session parameters!");
    }

    mVirtualCameraClientCallback->onConfigureSession(
        sessionParamsMetadata, mSessionContext.getCaptureResultConsumer());
  }

  if (mVirtualCameraClientCallback != nullptr && inputSurface != nullptr) {
    // TODO(b/301023410) Pass streamId based on client input stream id once
    // support for multiple input streams is implemented. For now we always
    // create single texture.
    mVirtualCameraClientCallback->onStreamConfigured(
        inputStreamId, aidl::android::view::Surface(inputSurface.get()),
        inputConfig->width, inputConfig->height, inputConfig->imageFormat);
  }

  // stop the render thread outside of the lock since it does a join() in its
  // destructor
  if (renderThread != nullptr) {
    renderThread->stop();
  }

  return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus VirtualCameraSession::configureMultiStream(
    const std::shared_ptr<VirtualCameraDevice> virtualCamera,
    const StreamConfiguration& requestedConfiguration,
    std::vector<HalStream>* halStreams) {
  (void)halStreams;

  std::map<int, int> outputToInputStreamMap;

  // If a currently-active stream is not included in streamList, the HAL may
  // safely remove any references to that stream. It must not be reused in a
  // later configureStreams() call by the framework, and all the gralloc
  // buffers for it must be freed after the configureStreams() call returns.

  // Check if we have an input surface with the desired resolution
  for (auto& stream : requestedConfiguration.streams) {
    std::optional<SupportedStreamConfiguration> inputConfig =
        pickInputConfigurationForStreams(std::vector<Stream>{stream},
                                         virtualCamera->getInputConfigs());

    ALOGV("configureMultiStream: inputConfig: %s",
          inputConfig->toString().c_str());

    if (inputConfig.has_value()) {
      // The virtual camera owner declared an input stream matching the
      // requested output stream
      std::lock_guard<std::mutex> lock(mLock);

      // Let's check if we already started a thread to read from this input surface
      if (!mRenderThreads.contains(inputConfig->index)) {
        createRenderThread(*virtualCamera, *inputConfig);
      }

      outputToInputStreamMap[stream.id] = inputConfig->index;

      VirtualCameraRenderThread* renderThread =
          mRenderThreads[inputConfig->index].get();

      renderThread->flush();
    } else {
      ALOGE("No input configuration found for %dx%d:%d", inputConfig->width,
            inputConfig->height, static_cast<int32_t>(inputConfig->imageFormat));
    }
  }

  // We pass the list of streams we have just opened or that we want
  // to keep open, and we get the list of streams we need to close.
  std::set<int> staleInputStreams =
      mSessionContext.updateOpenStreams(outputToInputStreamMap);

  for (int streamId : staleInputStreams) {
    ALOGV("configureMultiStream: closing input stream for thread id %d",
          streamId);
    if (mVirtualCameraClientCallback != nullptr) {
      mVirtualCameraClientCallback->onStreamClosed(streamId);
    }
  }

  // Now that the streams are closed, we can close the renderThread that were
  // using the closed streams
  closeUnusedRenderThreads();

  return ndk::ScopedAStatus::ok();
}

void VirtualCameraSession::createRenderThread(
    VirtualCameraDevice& virtualCamera,
    SupportedStreamConfiguration& inputConfig) {
  ALOGV("Creating new thread for inputConfig index: %d", inputConfig.index);
  std::unique_ptr<VirtualCameraRenderThread> newThread =
      std::make_unique<VirtualCameraRenderThread>(
          mSessionContext, inputConfig.index, inputConfig.imageFormat,
          resolutionFromInputConfig(inputConfig),
          virtualCamera.getMaxInputResolution(), mCameraDeviceCallback);
  newThread->start();

  if (mVirtualCameraClientCallback != nullptr) {
    ALOGV("calling onStreamConfigured for inputConfig: %s",
          inputConfig.toString().c_str());

    mVirtualCameraClientCallback->onStreamConfigured(
        inputConfig.index,
        aidl::android::view::Surface(newThread->getInputSurface().get()),
        inputConfig.width, inputConfig.height, inputConfig.imageFormat);
  }
  mRenderThreads[inputConfig.index] = std::move(newThread);
}

void VirtualCameraSession::closeUnusedRenderThreads() {
  // Remove render threads that are no longer needed
  std::vector<std::unique_ptr<VirtualCameraRenderThread>> threadsToStop;
  {
    std::lock_guard<std::mutex> lock(mLock);
    const std::set<int> usedInputStreamIds =
        mSessionContext.getUsedInputStreamIds();
    auto it = mRenderThreads.begin();
    while (it != mRenderThreads.end()) {
      auto& [streamId, renderThread] = *it;
      if (usedInputStreamIds.find(streamId) == usedInputStreamIds.end()) {
        ALOGV("Closing thread for input stream %d", streamId);
        threadsToStop.push_back(std::move(it->second));
        it = mRenderThreads.erase(it);
      } else {
        ++it;
      }
    }
  }

  for (auto& renderThread : threadsToStop) {
    renderThread->flush();
    renderThread->stop();
  }
}

ndk::ScopedAStatus VirtualCameraSession::constructDefaultRequestSettings(
    RequestTemplate in_type, CameraMetadata* _aidl_return) {
  if (isInFatalError()) {
    return cameraStatus(Status::INTERNAL_ERROR);
  }
  ALOGV("%s: type %d", __func__, static_cast<int32_t>(in_type));

  std::shared_ptr<VirtualCameraDevice> camera = mCameraDevice.lock();
  if (camera == nullptr) {
    ALOGW(
        "%s: constructDefaultRequestSettings called on already "
        "unregistered camera",
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
    default:
      ALOGE("%s: unknown request template type %d", __FUNCTION__,
            static_cast<int>(in_type));
      return ndk::ScopedAStatus::fromServiceSpecificError(
          static_cast<int32_t>(Status::ILLEGAL_ARGUMENT));
  }
}

ndk::ScopedAStatus VirtualCameraSession::flush() {
  if (isInFatalError()) {
    return cameraStatus(Status::INTERNAL_ERROR);
  }
  int flushFrame = mMaxFrameToFlush.exchange(-1, std::memory_order_relaxed);

  ALOGV("%s", __func__);
  std::lock_guard<std::mutex> lock(mLock);
  if (mRenderThread != nullptr) {
    mRenderThread->flush(flushFrame);
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
  ALOGV("%s: request count: %zu", __func__, in_requests.size());
  if (!in_cachesToRemove.empty()) {
    mSessionContext.removeBufferCaches(in_cachesToRemove);
  }

  for (const auto& captureRequest : in_requests) {
    auto status = processCaptureRequest(captureRequest);
    if (!status.isOk()) {
      ALOGE("%s failed to process request frameNumber:%d status:%s %s",
            __func__, captureRequest.frameNumber,
            status.getDescription().c_str(), status.getMessage());
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
  ALOGV("[%s] frameNumber:%d", __func__, in_frameNumber);
  (void)in_streamIds;
  mMaxFrameToFlush.store(in_frameNumber, std::memory_order_relaxed);
  return ndk::ScopedAStatus::ok();
}

std::set<int> VirtualCameraSession::getStreamIds() const {
  return mSessionContext.getStreamIds();
}

ndk::ScopedAStatus VirtualCameraSession::processCaptureRequest(
    const CaptureRequest& request) {
  ALOGV("%s: CaptureRequest { frameNumber:%d }", __func__, request.frameNumber);
  if (isInFatalError()) {
    return cameraStatus(Status::INTERNAL_ERROR);
  }

  std::shared_ptr<ICameraDeviceCallback> cameraCallback = nullptr;
  RequestSettings requestSettings;
  int currentInputStreamId;
  std::set<int> inputStreamIds;
  {
    std::lock_guard<std::mutex> lock(mLock);

    // If metadata is empty, last received metadata applies, if it's
    // non-empty update it.
    if (!request.settings.metadata.empty()) {
      mCurrentRequestMetadata = request.settings;
    }

    // We don't have any metadata for this request - this means we received
    // none in first request, this is an error state.
    if (mCurrentRequestMetadata.metadata.empty()) {
      return cameraStatus(Status::ILLEGAL_ARGUMENT);
    }

    requestSettings = createSettingsFromMetadata(mCurrentRequestMetadata);

    cameraCallback = mCameraDeviceCallback;
    currentInputStreamId = mCurrentInputStreamId;
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

    // Double check fatal error state while holding the lock to prevent
    // race conditions during teardown.
    if (isInFatalError()) {
      return cameraStatus(Status::INTERNAL_ERROR);
    }

    if (!mSessionContext.isMultiInputStreamEnabled()) {
      if (mRenderThread == nullptr) {
        ALOGE(
            "%s: processCaptureRequest (frameNumber %d) called before "
            "configure "
            "(render thread not initialized)",
            __func__, request.frameNumber);
        return cameraStatus(Status::INTERNAL_ERROR);
      }
      mRenderThread->enqueueTask(std::make_unique<ProcessCaptureRequestTask>(
          request.frameNumber, taskBuffers, requestSettings));
    } else {
      mSessionContext.enqueueFrame(request.frameNumber);

      // Map from inputStreamId to the buffers that should be filled by it.
      std::map<int, std::vector<CaptureRequestBuffer>> inputStreamToBuffersMap;
      for (const StreamBuffer& streamBuffer : request.outputBuffers) {
        int inputStreamId = mSessionContext.getInputStreamIdForOutputStreamId(
            streamBuffer.streamId);
        if (inputStreamId == kInvalidStreamId) {
          return cameraStatus(Status::ILLEGAL_ARGUMENT);
        }
        inputStreamToBuffersMap[inputStreamId].emplace_back(
            streamBuffer.streamId, streamBuffer.bufferId,
            importFence(streamBuffer.acquireFence));
        inputStreamIds.insert(inputStreamId);
      }

      for (auto& [inputStreamId, buffers] : inputStreamToBuffersMap) {
        ALOGV("%s, adding render task for renderThread:%d", __func__,
              inputStreamId);
        mRenderThreads[inputStreamId]->enqueueTask(
            std::make_unique<ProcessCaptureRequestTask>(
                request.frameNumber, buffers, requestSettings));
      }
    }
  }

  if (mVirtualCameraClientCallback != nullptr) {
    std::shared_ptr<VirtualCameraDevice> virtualCamera = mCameraDevice.lock();
    if (virtualCamera == nullptr) {
      ALOGW("%s: process capture request on unregistered camera", __func__);
      return cameraStatus(Status::CAMERA_DISCONNECTED);
    }

    std::optional<VirtualCameraMetadata> captureRequestSettings;
    if (virtualCamera->isPerFrameCameraMetadataEnabled()) {
      VirtualCameraMetadata virtualCameraMetadata;
      // Send the settings of the CaptureRequest as VirtualCameraMetadata
      status_t ret = convertDeviceToVirtualCameraMetadata(
          request.settings, virtualCameraMetadata);
      if (ret != OK) {
        ALOGE(
            "Failed to convert device to virtual capture request "
            "settings!");
      }
      captureRequestSettings = virtualCameraMetadata;
    }

    if (!mSessionContext.isMultiInputStreamEnabled()) {
      ndk::ScopedAStatus status =
          mVirtualCameraClientCallback->onProcessCaptureRequest(
              currentInputStreamId, request.frameNumber, captureRequestSettings);
      if (!status.isOk()) {
        ALOGE(
            "Failed to invoke onProcessCaptureRequest client callback for "
            "frame:%d currentInputStreamId:%d."
            "PerFrameCameraMetadataEnabled:%s. (error status:%s)",
            request.frameNumber, currentInputStreamId,
            virtualCamera->isPerFrameCameraMetadataEnabled() ? "true" : "false",
            status.getDescription().c_str());
      }
    } else {
      for (int streamId : inputStreamIds) {
        ndk::ScopedAStatus status =
            mVirtualCameraClientCallback->onProcessCaptureRequest(
                streamId, request.frameNumber, captureRequestSettings);
        if (!status.isOk()) {
          ALOGE(
              "Failed to invoke onProcessCaptureRequest client callback "
              "for stream:%d, frame:%d. PerFrameCameraMetadataEnabled:%s.",
              streamId, request.frameNumber,
              virtualCamera->isPerFrameCameraMetadataEnabled() ? "enabled"
                                                               : "disabled");
        }
      }
    }
  }

  return ndk::ScopedAStatus::ok();
}

void VirtualCameraSession::onSessionError() {
  ALOGW("Camera session error, notifying framework and stopping all streams.");
  {
    std::lock_guard<std::mutex> lock(mLock);
    // Don't call session close() since that removes the mThread(s) references,
    // hence calling the render thread destructor(s). If this is called from the
    // same thread, the join() from the destructor can deadlock. Flush the
    // single-stream render thread if it's being used.
    if (mRenderThread != nullptr) {
      mRenderThread->flush();
      mRenderThread->stop();
    }
    // Flush all multi-stream render threads if they are being used.
    for (auto& [_, thread] : mRenderThreads) {
      thread->flush();
      thread->stop();
    }
  }

  notifyDeviceError();
}

void VirtualCameraSession::notifyDeviceError() {
  std::shared_ptr<ICameraDeviceCallback> cameraDeviceCallback;
  {
    std::lock_guard<std::mutex> lock(mLock);
    cameraDeviceCallback = mCameraDeviceCallback;
  }

  if (cameraDeviceCallback != nullptr) {
    NotifyMsg msg;
    msg.set<NotifyMsg::Tag::error>(
        ErrorMsg{.frameNumber = -1,
                 .errorStreamId = -1,
                 .errorCode = ErrorCode::ERROR_DEVICE});
    cameraDeviceCallback->notify({msg});
  }
}

}  // namespace virtualcamera
}  // namespace companion
}  // namespace android
