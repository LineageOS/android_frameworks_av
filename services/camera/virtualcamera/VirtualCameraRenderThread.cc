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
#define LOG_TAG "VirtualCameraRenderThread"

#include "VirtualCameraRenderThread.h"

#include <android_companion_virtualdevice_flags.h>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <future>
#include <memory>
#include <mutex>
#include <thread>
#include <utility>
#include <vector>

#include "VirtualCameraCaptureResult.h"
#include "VirtualCameraDevice.h"
#include "VirtualCameraImageHandler.h"
#include "VirtualCameraImagePassthroughHandler.h"
#include "VirtualCameraImageTransformingHandler.h"
#include "VirtualCameraSessionContext.h"
#include "aidl/android/hardware/camera/common/Status.h"
#include "aidl/android/hardware/camera/device/BufferStatus.h"
#include "aidl/android/hardware/camera/device/CameraMetadata.h"
#include "aidl/android/hardware/camera/device/CaptureResult.h"
#include "aidl/android/hardware/camera/device/ErrorCode.h"
#include "aidl/android/hardware/camera/device/ICameraDeviceCallback.h"
#include "aidl/android/hardware/camera/device/NotifyMsg.h"
#include "aidl/android/hardware/camera/device/ShutterMsg.h"
#include "aidl/android/hardware/camera/device/StreamBuffer.h"
#include "android-base/thread_annotations.h"
#include "android/binder_auto_utils.h"
#include "android/hardware_buffer.h"
#include "system/camera_metadata.h"
#include "ui/GraphicBuffer.h"
#include "util/Util.h"
#include "utils/Errors.h"

namespace android {
namespace companion {
namespace virtualcamera {

using ::aidl::android::companion::virtualcamera::Format;
using ::aidl::android::hardware::camera::common::Status;
using ::aidl::android::hardware::camera::device::BufferStatus;
using ::aidl::android::hardware::camera::device::CameraMetadata;
using ::aidl::android::hardware::camera::device::CaptureResult;
using ::aidl::android::hardware::camera::device::ErrorCode;
using ::aidl::android::hardware::camera::device::ErrorMsg;
using ::aidl::android::hardware::camera::device::ICameraDeviceCallback;
using ::aidl::android::hardware::camera::device::NotifyMsg;
using ::aidl::android::hardware::camera::device::ShutterMsg;
using ::aidl::android::hardware::camera::device::Stream;
using ::aidl::android::hardware::camera::device::StreamBuffer;
using ::aidl::android::hardware::graphics::common::PixelFormat;
using ::android::base::ScopedLockAssertion;

using ::android::hardware::camera::common::helper::ExifUtils;

namespace {

// helper type for the visitor
template <class... Ts>
struct overloaded : Ts... {
  using Ts::operator()...;
};
// explicit deduction guide (not needed as of C++20)
template <class... Ts>
overloaded(Ts...) -> overloaded<Ts...>;

using namespace std::chrono_literals;

namespace flags = ::android::companion::virtualdevice::flags;

static constexpr UpdateTextureTask kUpdateTextureTask;

// The number of nanoseconds to wait for the first frame to be drawn on the
// input surface
static constexpr std::chrono::nanoseconds kMaxWaitFirstFrame = 15s;
// The number of nanoseconds to wait for a frame for use cases where frame
// duplication is not an option.
static constexpr std::chrono::nanoseconds kMaxWaitNoDuplication = 60s;

static constexpr double kOneSecondInNanos = 1e9;

NotifyMsg createShutterNotifyMsg(int frameNumber,
                                 std::chrono::nanoseconds timestamp) {
  NotifyMsg msg;
  msg.set<NotifyMsg::Tag::shutter>(ShutterMsg{
      .frameNumber = frameNumber,
      .timestamp = timestamp.count(),
  });
  return msg;
}

// Create a NotifyMsg for an error case. The default error is ERROR_BUFFER.
NotifyMsg createErrorNotifyMsg(int frameNumber, int streamId,
                               ErrorCode errorCode = ErrorCode::ERROR_BUFFER) {
  NotifyMsg msg;
  msg.set<NotifyMsg::Tag::error>(ErrorMsg{.frameNumber = frameNumber,
                                          .errorStreamId = streamId,
                                          .errorCode = errorCode});
  return msg;
}

NotifyMsg createRequestErrorNotifyMsg(int frameNumber) {
  NotifyMsg msg;
  msg.set<NotifyMsg::Tag::error>(
      ErrorMsg{.frameNumber = frameNumber,
               // errorStreamId needs to be set to -1 for ERROR_REQUEST
               // (not tied to specific stream).
               .errorStreamId = -1,
               .errorCode = ErrorCode::ERROR_REQUEST});
  return msg;
}

// By default, virtual camera will duplicate the last frame if the producer does
// not post a new frame. When a frame is duplicated, the timestamp must still
// increase to please the camera framework expectations. In some usecases, this
// frame duplication is not wanted, like for motion tracking, where the
// timestamp must match the graphic data.
bool allowFrameDuplication(const RequestSettings& requestSettings) {
  if (!flags::virtual_camera_no_frame_duplication()) {
    return true;
  }
  if (requestSettings.captureIntent == ANDROID_CONTROL_CAPTURE_INTENT_PREVIEW) {
    return true;
  }

  return false;
}

std::chrono::nanoseconds getMaxFrameDuration(
    const RequestSettings& requestSettings, bool isFirstFrameDrawn) {
  // If it's not the first frame and the request specify a FPS, return the minFps
  if (isFirstFrameDrawn && requestSettings.fpsRange.has_value()) {
    return std::chrono::nanoseconds(static_cast<uint64_t>(
        kOneSecondInNanos / std::max(1, requestSettings.fpsRange->minFps)));
  }

  // If the request does not specify a FPS and we should not duplicate frames,
  // wait as much as we can
  if (!allowFrameDuplication(requestSettings)) {
    return kMaxWaitNoDuplication;
  }

  // If we can duplicate frame but nothing has been drawn on the suface yet, we
  // allow ourselves to wait a bit longer
  if (!isFirstFrameDrawn) {
    return kMaxWaitFirstFrame;
  }

  // In all other cases we wait for the duration of kMinFps
  return std::chrono::nanoseconds(
      static_cast<uint64_t>(kOneSecondInNanos / VirtualCameraDevice::kMinFps));
}

// Translate a frame duration into a fps value with triple decimal precision
double nanosToFps(std::chrono::nanoseconds frameDuration) {
  const double oneSecondInNanos = 1e9;
  const double fpsNanos = oneSecondInNanos / frameDuration.count();
  return fpsNanos;
}

}  // namespace

VirtualCameraRenderThread::VirtualCameraRenderThread(
    VirtualCameraSessionContext& sessionContext, Format imageFormat,
    const Resolution inputSurfaceSize, const Resolution reportedSensorSize,
    std::shared_ptr<ICameraDeviceCallback> cameraDeviceCallback)
    : mCameraDeviceCallback(cameraDeviceCallback),
      mImageFormat{imageFormat},
      mInputSurfaceSize(inputSurfaceSize),
      mReportedSensorSize(reportedSensorSize),
      mSessionContext(sessionContext),
      mInputSurfaceFuture(mInputSurfacePromise.get_future()) {
}

VirtualCameraRenderThread::~VirtualCameraRenderThread() {
  stop();
  if (mThread.joinable()) {
    mThread.join();
  }
}

ProcessCaptureRequestTask::ProcessCaptureRequestTask(
    int frameNumber, const std::vector<CaptureRequestBuffer>& requestBuffers,
    const RequestSettings& requestSettings)
    : mFrameNumber(frameNumber),
      mBuffers(requestBuffers),
      mRequestSettings(requestSettings) {
}

int ProcessCaptureRequestTask::getFrameNumber() const {
  return mFrameNumber;
}

const std::vector<CaptureRequestBuffer>& ProcessCaptureRequestTask::getBuffers()
    const {
  return mBuffers;
}

const RequestSettings& ProcessCaptureRequestTask::getRequestSettings() const {
  return mRequestSettings;
}

void VirtualCameraRenderThread::requestTextureUpdate() {
  std::lock_guard<std::mutex> lock(mLock);
  ALOGV("%s", __func__);
  // If queue is not empty, we don't need to set the mTextureUpdateRequested
  // flag, since the texture will be updated during ProcessCaptureRequestTask
  // processing anyway.
  if (mQueue.empty()) {
    mTextureUpdateRequested = true;
    mCondVar.notify_one();
  }
}

void VirtualCameraRenderThread::enqueueTask(
    std::unique_ptr<ProcessCaptureRequestTask> task) {
  std::lock_guard<std::mutex> lock(mLock);
  // When enqueving process capture request task, clear the
  // mTextureUpdateRequested flag. If this flag is set, the texture was not yet
  // updated and it will be updated when processing ProcessCaptureRequestTask
  // anyway.
  mTextureUpdateRequested = false;
  mQueue.emplace_back(std::move(task));
  mCondVar.notify_one();
}

void VirtualCameraRenderThread::flush() {
  std::lock_guard<std::mutex> lock(mLock);
  while (!mQueue.empty()) {
    std::unique_ptr<ProcessCaptureRequestTask> task = std::move(mQueue.front());
    mQueue.pop_front();
    flushCaptureRequest(*task);
  }
}

bool VirtualCameraRenderThread::start() {
  mImageHandlerInitialized = std::promise<bool>{};
  mThread = std::thread(&VirtualCameraRenderThread::threadLoop, this);
  return mImageHandlerInitialized.get_future().get();
}

void VirtualCameraRenderThread::stop() {
  {
    std::lock_guard<std::mutex> lock(mLock);
    mPendingExit = true;
    mCondVar.notify_one();
  }
}

sp<Surface> VirtualCameraRenderThread::getInputSurface() {
  return mInputSurfaceFuture.get();
}

Format VirtualCameraRenderThread::getImageFormat() const {
  return mImageFormat;
}

const Resolution& VirtualCameraRenderThread::getInputResolution() const {
  return mInputSurfaceSize;
}

RenderThreadTask VirtualCameraRenderThread::dequeueTask() {
  std::unique_lock<std::mutex> lock(mLock);
  // Clang's thread safety analysis doesn't perform alias analysis,
  // so it doesn't support moveable std::unique_lock.
  //
  // Lock assertion below is basically explicit declaration that
  // the lock is held in this scope, which is true, since it's only
  // released during waiting inside mCondVar.wait calls.
  ScopedLockAssertion lockAssertion(mLock);

  mCondVar.wait(lock, [this]() REQUIRES(mLock) {
    return mPendingExit || mTextureUpdateRequested || !mQueue.empty();
  });
  if (mPendingExit) {
    // Render thread task with null task signals render thread to terminate.
    return RenderThreadTask(nullptr);
  }
  if (mTextureUpdateRequested) {
    // If mTextureUpdateRequested, it's guaranteed the queue is empty, return
    // kUpdateTextureTask to signal we want render thread to update the texture
    // (consume buffer from the queue).
    mTextureUpdateRequested = false;
    return RenderThreadTask(kUpdateTextureTask);
  }
  RenderThreadTask task(std::move(mQueue.front()));
  mQueue.pop_front();
  return task;
}

void VirtualCameraRenderThread::threadLoop() {
  ALOGV("Render thread starting");

  if (!initializeImageHandler()) {
    ALOGE("%s: Failed to initialize frame consumer", __func__);
    mImageHandlerInitialized.set_value(false);
    return;
  }

  mImageHandlerInitialized.set_value(true);

  while (RenderThreadTask task = dequeueTask()) {
    std::visit(
        overloaded{[this](const std::unique_ptr<ProcessCaptureRequestTask>& t) {
                     processTask(*t);
                   },
                   [this](const UpdateTextureTask&) {
                     ALOGV("Idle update of the texture");
                     mImageHandler->updateTexture();
                   }},
        task);
  }

  mImageHandler.reset();
  mInputSurfaceFuture.get()->destroy();
  ALOGV("Render thread exiting");
}

void VirtualCameraRenderThread::processTask(
    const ProcessCaptureRequestTask& request) {
  ALOGV("%s Request frame number: %d, capture intent %d", __func__,
        request.getFrameNumber(), request.getRequestSettings().captureIntent);
  std::chrono::nanoseconds deviceTime =
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          std::chrono::steady_clock::now().time_since_epoch());
  const std::chrono::nanoseconds lastAcquisitionTimestamp(
      mLastAcquisitionTimestampNanoseconds.load(std::memory_order_relaxed));

  ALOGV("lastAcquisitionTimestamp %lld", lastAcquisitionTimestamp.count());

  // Calculate the maximal amount of time we can afford to wait for next frame.
  const bool isFirstFrameDrawn = mImageHandler->isFirstFrameDrawn();
  ALOGV("First Frame Drawn: %s", isFirstFrameDrawn ? "Yes" : "No");

  std::chrono::nanoseconds maxFrameDuration =
      getMaxFrameDuration(request.getRequestSettings(), isFirstFrameDrawn);
  std::chrono::nanoseconds elapsedDuration =
      isFirstFrameDrawn && lastAcquisitionTimestamp > 0ns
          ? deviceTime - lastAcquisitionTimestamp
          : 0ns;

  bool gotNewFrame = false;
  const std::chrono::nanoseconds waitTime =
      std::max(0ns, maxFrameDuration - elapsedDuration);
  ALOGV("maxFrameDuration %lld, elapsedDuration %lld, waitTime %lld",
        maxFrameDuration.count(), elapsedDuration.count(), waitTime.count());
  if (waitTime > 0ns) {
    // We can afford to wait for next frame.
    // Note that if there's already new frame in the input Surface, the call
    // below returns immediately.
    gotNewFrame = mImageHandler->waitForInputFrame(waitTime);
  }

  if (!gotNewFrame) {
    ALOGV(
        "%s: No new frame received on input surface after waiting for "
        "%.3f s",
        __func__, static_cast<uint64_t>(waitTime.count()) / kOneSecondInNanos);

    if (!allowFrameDuplication(request.getRequestSettings()) ||
        !mImageHandler->isFirstFrameDrawn()) {
      // We don't have any input ever drawn. This is considered as an error
      // case. Notify the framework of the failure and return early.
      ALOGW("Timed out waiting for frame to be posted.");
      std::unique_ptr<CaptureResult> captureResult = createCaptureResult(
          request.getFrameNumber(), /* metadata = */ nullptr);
      notifyTimeout(request, *captureResult);
      submitCaptureResult(std::move(captureResult));
      return;
    }
  }

  // If the request has a maxFps, we throttle the rendering to make sure that
  // the requester receives the latest frame that was posted by the virtual
  // camera in the interval :
  //  [last acquisition time, last acquisition time + maxFps].
  //
  // So if the virtual camera renders faster than the requested frame, the
  // requester won't be receiving unnecessary frames.
  if (request.getRequestSettings().fpsRange) {
    ALOGV("%s request fps {%d,%d}", __func__,
          request.getRequestSettings().fpsRange->minFps,
          request.getRequestSettings().fpsRange->maxFps);
    int maxFps = std::max(1, request.getRequestSettings().fpsRange->maxFps);
    throttleRendering(maxFps, lastAcquisitionTimestamp);
  }

  // Acquire new (most recent) image from the Surface.
  mImageHandler->updateTexture();

  // Now that throttling and waiting have been done, update the acquisition timestamp.
  deviceTime = std::chrono::duration_cast<std::chrono::nanoseconds>(
      std::chrono::steady_clock::now().time_since_epoch());

  elapsedDuration = isFirstFrameDrawn && lastAcquisitionTimestamp > 0ns
                        ? deviceTime - lastAcquisitionTimestamp
                        : 0ns;

  mLastAcquisitionTimestampNanoseconds.store(deviceTime.count(),
                                             std::memory_order_relaxed);

  std::chrono::nanoseconds captureTimestamp = deviceTime;
  if (flags::camera_timestamp_from_surface()) {
    std::chrono::nanoseconds surfaceTimestamp =
        getSurfaceTimestamp(elapsedDuration);
    if (surfaceTimestamp.count() > 0) {
      captureTimestamp = surfaceTimestamp;
    }
    ALOGV(
        "%s surfaceTimestamp:%lld deviceTime:%lld captureTimestamp:%lld "
        "(nanos)",
        __func__, surfaceTimestamp.count(), deviceTime.count(),
        captureTimestamp.count());
  }

  const camera_metadata_t* customMetadata =
      mSessionContext.getCaptureResultMetadataForTimestamp(
          captureTimestamp.count());

  std::unique_ptr<CaptureResult> captureResult = createCaptureResult(
      request.getFrameNumber(),
      createCaptureResultMetadata(
          captureTimestamp, request.getRequestSettings(), mReportedSensorSize,
          customMetadata));

  if (customMetadata != nullptr) {
    free_camera_metadata(const_cast<camera_metadata_t*>(customMetadata));
  }

  renderOutputBuffers(request, *captureResult);

  auto status = notifyShutter(request, *captureResult, captureTimestamp);
  if (!status.isOk()) {
    ALOGE("%s: notify call failed: %s", __func__,
          status.getDescription().c_str());
    return;
  }
  submitCaptureResult(std::move(captureResult));
}

void VirtualCameraRenderThread::throttleRendering(
    int maxFps, std::chrono::nanoseconds lastAcquisitionTimestamp) {
  if (lastAcquisitionTimestamp <= 0ns) {
    // It's our first request, there is nothing to throttle.
    return;
  }
  std::chrono::nanoseconds timestamp =
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          std::chrono::steady_clock::now().time_since_epoch());

  const std::chrono::nanoseconds minFrameDuration(
      static_cast<uint64_t>(1e9 / maxFps));
  const std::chrono::nanoseconds frameDuration =
      timestamp - lastAcquisitionTimestamp;
  if (frameDuration < minFrameDuration) {
    // We're too fast for the configured maxFps, let's wait a bit.
    const std::chrono::nanoseconds sleepTime = minFrameDuration - frameDuration;
    ALOGV("Current frame duration would be %" PRIu64
          " ns corresponding to %.3f Fps, "
          "sleeping for %" PRIu64
          " ns before updating texture to match maxFps %d",
          static_cast<uint64_t>(frameDuration.count()),
          nanosToFps(frameDuration), static_cast<uint64_t>(sleepTime.count()),
          maxFps);

    std::chrono::nanoseconds beforeSleep =
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch());
    std::this_thread::sleep_for(sleepTime);
    std::chrono::nanoseconds after_sleep =
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch());
    ALOGV("actual sleep time %lld (%.3f)", (after_sleep - beforeSleep).count(),
          nanosToFps(after_sleep - lastAcquisitionTimestamp));
  } else {
    ALOGV("Current frame is %" PRIu64
          " ns corresponding to %.3f Fps, "
          "no need to sleep to match maxFps %d",
          static_cast<uint64_t>(frameDuration.count()),
          nanosToFps(frameDuration), maxFps);
  }
}

std::chrono::nanoseconds VirtualCameraRenderThread::getSurfaceTimestamp(
    std::chrono::nanoseconds timeSinceLastFrame) {
  std::chrono::nanoseconds surfaceTimestamp = mImageHandler->getTimestamp();
  uint64_t lastSurfaceTimestamp = mLastSurfaceTimestampNanoseconds.load();
  if (lastSurfaceTimestamp > 0 &&
      surfaceTimestamp.count() <= lastSurfaceTimestamp) {
    // The timestamps were provided by the producer but we are
    // repeating the last frame, so we increase the previous timestamp by
    // the elapsed time since its capture, otherwise the camera framework
    // will discard the frame.
    surfaceTimestamp = std::chrono::nanoseconds(lastSurfaceTimestamp +
                                                timeSinceLastFrame.count());
    ALOGI(
        "Surface's timestamp is stall. Artificially increasing the surface "
        "timestamp by %lld",
        timeSinceLastFrame.count());
  }
  mLastSurfaceTimestampNanoseconds.store(surfaceTimestamp.count(),
                                         std::memory_order_relaxed);
  return surfaceTimestamp;
}

std::unique_ptr<CaptureResult> VirtualCameraRenderThread::createCaptureResult(
    int frameNumber, std::unique_ptr<CameraMetadata> metadata) {
  std::unique_ptr<CaptureResult> captureResult =
      std::make_unique<CaptureResult>();
  captureResult->fmqResultSize = 0;
  captureResult->frameNumber = frameNumber;
  // Partial result needs to be set to 1 when metadata are present.
  captureResult->partialResult = 1;
  captureResult->inputBuffer.streamId = -1;
  captureResult->physicalCameraMetadata.resize(0);
  captureResult->result = metadata != nullptr ? *metadata : CameraMetadata();
  return captureResult;
}

void VirtualCameraRenderThread::renderOutputBuffers(
    const ProcessCaptureRequestTask& request, CaptureResult& captureResult) {
  const std::vector<CaptureRequestBuffer>& buffers = request.getBuffers();
  captureResult.outputBuffers.resize(buffers.size());

  for (int i = 0; i < buffers.size(); ++i) {
    const CaptureRequestBuffer& reqBuffer = buffers[i];
    StreamBuffer& resBuffer = captureResult.outputBuffers[i];
    resBuffer.streamId = reqBuffer.getStreamId();
    resBuffer.bufferId = reqBuffer.getBufferId();
    resBuffer.status = BufferStatus::OK;

    ALOGV("%s : rendering buffer %" PRId64 " for stream id %" PRId32, __func__,
          resBuffer.bufferId, resBuffer.streamId);

    const std::optional<Stream> streamConfig =
        mSessionContext.getStreamConfig(reqBuffer.getStreamId());

    if (!streamConfig.has_value()) {
      resBuffer.status = BufferStatus::ERROR;
      continue;
    }

    auto status = mImageHandler->fillOutputBuffer(
        request.getRequestSettings(), reqBuffer, *streamConfig, captureResult);
    if (!status.isOk()) {
      resBuffer.status = BufferStatus::ERROR;
    }
  }
}

::ndk::ScopedAStatus VirtualCameraRenderThread::notifyTimeout(
    const ProcessCaptureRequestTask& request, CaptureResult& captureResult) {
  const std::vector<CaptureRequestBuffer>& buffers = request.getBuffers();
  captureResult.outputBuffers.resize(buffers.size());

  std::vector<NotifyMsg> notifyMsgs;

  for (int i = 0; i < buffers.size(); ++i) {
    const CaptureRequestBuffer& reqBuffer = buffers[i];
    StreamBuffer& resBuffer = captureResult.outputBuffers[i];
    resBuffer.streamId = reqBuffer.getStreamId();
    resBuffer.bufferId = reqBuffer.getBufferId();
    resBuffer.status = BufferStatus::ERROR;
    notifyMsgs.push_back(createErrorNotifyMsg(
        request.getFrameNumber(), resBuffer.streamId, ErrorCode::ERROR_REQUEST));
  }
  return mCameraDeviceCallback->notify(notifyMsgs);
}

::ndk::ScopedAStatus VirtualCameraRenderThread::notifyShutter(
    const ProcessCaptureRequestTask& request, const CaptureResult& captureResult,
    std::chrono::nanoseconds captureTimestamp) {
  std::vector<NotifyMsg> notifyMsgs{
      createShutterNotifyMsg(request.getFrameNumber(), captureTimestamp)};
  for (const StreamBuffer& resBuffer : captureResult.outputBuffers) {
    if (resBuffer.status != BufferStatus::OK) {
      notifyMsgs.push_back(
          createErrorNotifyMsg(request.getFrameNumber(), resBuffer.streamId));
    }
  }

  return mCameraDeviceCallback->notify(notifyMsgs);
}

::ndk::ScopedAStatus VirtualCameraRenderThread::submitCaptureResult(
    std::unique_ptr<CaptureResult> captureResult) {
  std::vector<::aidl::android::hardware::camera::device::CaptureResult>
      captureResults;
  captureResults.push_back(std::move(*captureResult));

  ::ndk::ScopedAStatus status =
      mCameraDeviceCallback->processCaptureResult(captureResults);
  if (!status.isOk()) {
    ALOGE("%s: processCaptureResult call failed: %s", __func__,
          status.getDescription().c_str());
    return status;
  }

  ALOGV("%s: Successfully called processCaptureResult", __func__);
  return status;
}

void VirtualCameraRenderThread::flushCaptureRequest(
    const ProcessCaptureRequestTask& request) {
  CaptureResult captureResult;
  captureResult.fmqResultSize = 0;
  captureResult.frameNumber = request.getFrameNumber();
  captureResult.inputBuffer.streamId = -1;

  const std::vector<CaptureRequestBuffer>& buffers = request.getBuffers();
  captureResult.outputBuffers.resize(buffers.size());

  for (int i = 0; i < buffers.size(); ++i) {
    const CaptureRequestBuffer& reqBuffer = buffers[i];
    StreamBuffer& resBuffer = captureResult.outputBuffers[i];
    resBuffer.streamId = reqBuffer.getStreamId();
    resBuffer.bufferId = reqBuffer.getBufferId();
    resBuffer.status = BufferStatus::ERROR;
    sp<Fence> fence = reqBuffer.getFence();
    if (fence != nullptr && fence->isValid()) {
      resBuffer.releaseFence.fds.emplace_back(fence->dup());
    }
  }

  auto status = mCameraDeviceCallback->notify(
      {createRequestErrorNotifyMsg(request.getFrameNumber())});
  if (!status.isOk()) {
    ALOGE("%s: notify call failed: %s", __func__,
          status.getDescription().c_str());
    return;
  }

  std::vector<::aidl::android::hardware::camera::device::CaptureResult>
      captureResults(1);
  captureResults[0] = std::move(captureResult);

  status = mCameraDeviceCallback->processCaptureResult(captureResults);
  if (!status.isOk()) {
    ALOGE("%s: processCaptureResult call failed: %s", __func__,
          status.getDescription().c_str());
  }
}

bool VirtualCameraRenderThread::initializeImageHandler() {
  // TODO(b/458613942): Currently a BLOB input can only be used for direct
  // passthrough. Add the ability to decode the BLOB format, which will enable
  // the ability to satisfy bitmap stream requests as well from the same input.
  if (isBlobFormat(mImageFormat)) {
    auto imagePassthroughHandler = VirtualCameraImagePassthroughHandler::create(
        mSessionContext, mImageFormat, [this] { requestTextureUpdate(); });

    if (!imagePassthroughHandler) {
      ALOGE("%s: failed to initialize VirtualCameraImagePassthroughHandler",
            __func__);
      return false;
    }
    mImageHandler = std::move(imagePassthroughHandler);

  } else {
    mImageHandler = std::make_unique<VirtualCameraImageTransformingHandler>(
        mSessionContext, mInputSurfaceSize, [this] { requestTextureUpdate(); });
  }

  mInputSurfacePromise.set_value(mImageHandler->getInputSurface());
  return true;
}

}  // namespace virtualcamera
}  // namespace companion
}  // namespace android
