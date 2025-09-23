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

#include "Exif.h"
#include "GLES/gl.h"
#include "VirtualCameraCaptureResult.h"
#include "VirtualCameraDevice.h"
#include "VirtualCameraSessionContext.h"
#include "aidl/android/hardware/camera/common/Status.h"
#include "aidl/android/hardware/camera/device/BufferStatus.h"
#include "aidl/android/hardware/camera/device/CameraBlob.h"
#include "aidl/android/hardware/camera/device/CameraBlobId.h"
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
#include "ui/Rect.h"
#include "util/EglFramebuffer.h"
#include "util/JpegUtil.h"
#include "util/Util.h"
#include "utils/Errors.h"

namespace android {
namespace companion {
namespace virtualcamera {

using ::aidl::android::hardware::camera::common::Status;
using ::aidl::android::hardware::camera::device::BufferStatus;
using ::aidl::android::hardware::camera::device::CameraBlob;
using ::aidl::android::hardware::camera::device::CameraBlobId;
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

static constexpr std::chrono::milliseconds kAcquireFenceTimeout = 500ms;

static constexpr size_t kJpegThumbnailBufferSize = 32 * 1024;  // 32 KiB

static constexpr UpdateTextureTask kUpdateTextureTask;

// The number of nanosecond to wait for the first frame to be drawn on the input surface
static constexpr std::chrono::nanoseconds kMaxWaitFirstFrame = 3s;
// The number of nanosecond to wait for a frame for use cases where frame
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

std::shared_ptr<EglFrameBuffer> allocateTemporaryFramebuffer(
    EGLDisplay eglDisplay, const uint width, const int height) {
  const AHardwareBuffer_Desc desc{.width = static_cast<uint32_t>(width),
                                  .height = static_cast<uint32_t>(height),
                                  .layers = 1,
                                  .format = kHardwareBufferFormat,
                                  .usage = kHardwareBufferUsage,
                                  .rfu0 = 0,
                                  .rfu1 = 0};

  AHardwareBuffer* hwBufferPtr;
  int status = AHardwareBuffer_allocate(&desc, &hwBufferPtr);
  if (status != NO_ERROR) {
    ALOGE(
        "%s: Failed to allocate hardware buffer for temporary framebuffer: %d",
        __func__, status);
    return nullptr;
  }

  return std::make_shared<EglFrameBuffer>(
      eglDisplay,
      std::shared_ptr<AHardwareBuffer>(hwBufferPtr, AHardwareBuffer_release));
}

bool isYuvFormat(const PixelFormat pixelFormat) {
  switch (static_cast<android_pixel_format_t>(pixelFormat)) {
    case HAL_PIXEL_FORMAT_YCBCR_422_I:
    case HAL_PIXEL_FORMAT_YCBCR_422_SP:
    case HAL_PIXEL_FORMAT_Y16:
    case HAL_PIXEL_FORMAT_YV12:
    case HAL_PIXEL_FORMAT_YCBCR_420_888:
      return true;
    default:
      return false;
  }
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

std::vector<uint8_t> createExif(
    Resolution imageSize, const CameraMetadata resultMetadata,
    const std::vector<uint8_t>& compressedThumbnail = {}) {
  std::unique_ptr<ExifUtils> exifUtils(ExifUtils::create());
  exifUtils->initialize();

  // Make a copy of the metadata in order to converting it the HAL metadata
  // format (as opposed to the AIDL class) and use the setFromMetadata method
  // from ExifUtil
  camera_metadata_t* rawSettings =
      clone_camera_metadata((camera_metadata_t*)resultMetadata.metadata.data());
  if (rawSettings != nullptr) {
    android::hardware::camera::common::helper::CameraMetadata halMetadata(
        rawSettings);
    exifUtils->setFromMetadata(halMetadata, imageSize.width, imageSize.height);
  }
  exifUtils->setMake(VirtualCameraDevice::kDefaultMakeAndModel);
  exifUtils->setModel(VirtualCameraDevice::kDefaultMakeAndModel);
  exifUtils->setFlash(0);

  std::vector<uint8_t> app1Data;

  size_t thumbnailDataSize = compressedThumbnail.size();
  const void* thumbnailData =
      thumbnailDataSize > 0
          ? reinterpret_cast<const void*>(compressedThumbnail.data())
          : nullptr;

  if (!exifUtils->generateApp1(thumbnailData, thumbnailDataSize)) {
    ALOGE("%s: Failed to generate APP1 segment for EXIF metadata", __func__);
    return app1Data;
  }

  const uint8_t* data = exifUtils->getApp1Buffer();
  const size_t size = exifUtils->getApp1Length();

  app1Data.insert(app1Data.end(), data, data + size);
  return app1Data;
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

CaptureRequestBuffer::CaptureRequestBuffer(int streamId, int bufferId,
                                           sp<Fence> fence)
    : mStreamId(streamId), mBufferId(bufferId), mFence(fence) {
}

int CaptureRequestBuffer::getStreamId() const {
  return mStreamId;
}

int CaptureRequestBuffer::getBufferId() const {
  return mBufferId;
}

sp<Fence> CaptureRequestBuffer::getFence() const {
  return mFence;
}

VirtualCameraRenderThread::VirtualCameraRenderThread(
    VirtualCameraSessionContext& sessionContext,
    const Resolution inputSurfaceSize, const Resolution reportedSensorSize,
    std::shared_ptr<ICameraDeviceCallback> cameraDeviceCallback)
    : mCameraDeviceCallback(cameraDeviceCallback),
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

void VirtualCameraRenderThread::start() {
  mThread = std::thread(&VirtualCameraRenderThread::threadLoop, this);
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

  mEglDisplayContext = std::make_unique<EglDisplayContext>();
  mEglTextureYuvProgram =
      std::make_unique<EglTextureProgram>(EglTextureProgram::TextureFormat::YUV);
  mEglTextureRgbProgram = std::make_unique<EglTextureProgram>(
      EglTextureProgram::TextureFormat::RGBA);
  mEglSurfaceTexture = std::make_unique<EglSurfaceTexture>(
      mInputSurfaceSize.width, mInputSurfaceSize.height);
  mEglSurfaceTexture->setFrameAvailableListener(
      [this]() { requestTextureUpdate(); });

  mInputSurfacePromise.set_value(mEglSurfaceTexture->getSurface());

  while (RenderThreadTask task = dequeueTask()) {
    std::visit(
        overloaded{[this](const std::unique_ptr<ProcessCaptureRequestTask>& t) {
                     processTask(*t);
                   },
                   [this](const UpdateTextureTask&) {
                     ALOGV("Idle update of the texture");
                     mEglSurfaceTexture->updateTexture();
                   }},
        task);
  }

  // Destroy EGL utilities still on the render thread.
  mEglSurfaceTexture.reset();
  mEglTextureRgbProgram.reset();
  mEglTextureYuvProgram.reset();
  mEglDisplayContext.reset();

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
  const bool isFirstFrameDrawn = mEglSurfaceTexture->isFirstFrameDrawn();
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
    gotNewFrame = mEglSurfaceTexture->waitForNextFrame(waitTime);
  }

  if (!gotNewFrame) {
    ALOGV(
        "%s: No new frame received on input surface after waiting for "
        "%.3f s",
        __func__, static_cast<uint64_t>(waitTime.count()) / kOneSecondInNanos);

    if (!allowFrameDuplication(request.getRequestSettings()) ||
        !mEglSurfaceTexture->isFirstFrameDrawn()) {
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
  mEglSurfaceTexture->updateTexture();

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
  std::chrono::nanoseconds surfaceTimestamp = mEglSurfaceTexture->getTimestamp();
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

    auto status = streamConfig->format == PixelFormat::BLOB
                      ? renderIntoBlobStreamBuffer(
                            reqBuffer.getStreamId(), reqBuffer.getBufferId(),
                            captureResult.result, request.getRequestSettings(),
                            reqBuffer.getFence())
                      : renderIntoImageStreamBuffer(reqBuffer.getStreamId(),
                                                    reqBuffer.getBufferId(),
                                                    reqBuffer.getFence());
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

std::vector<uint8_t> VirtualCameraRenderThread::createThumbnail(
    const Resolution resolution, const int quality) {
  if (resolution.width == 0 || resolution.height == 0) {
    ALOGV("%s: Skipping thumbnail creation, zero size requested", __func__);
    return {};
  }

  ALOGV("%s: Creating thumbnail with size %d x %d, quality %d", __func__,
        resolution.width, resolution.height, quality);
  Resolution bufferSize = roundTo2DctSize(resolution);
  std::shared_ptr<EglFrameBuffer> framebuffer = allocateTemporaryFramebuffer(
      mEglDisplayContext->getEglDisplay(), bufferSize.width, bufferSize.height);
  if (framebuffer == nullptr) {
    ALOGE(
        "Failed to allocate temporary framebuffer for JPEG thumbnail "
        "compression");
    return {};
  }

  // TODO(b/324383963) Add support for letterboxing if the thumbnail sizese
  // doesn't correspond
  //  to input texture aspect ratio.
  if (!renderIntoEglFramebuffer(*framebuffer, /*fence=*/nullptr,
                                Rect(resolution.width, resolution.height))
           .isOk()) {
    ALOGE(
        "Failed to render input texture into temporary framebuffer for JPEG "
        "thumbnail");
    return {};
  }

  std::vector<uint8_t> compressedThumbnail;
  compressedThumbnail.resize(kJpegThumbnailBufferSize);
  ALOGE("%s: Compressing thumbnail %d x %d", __func__, resolution.width,
        resolution.height);
  std::optional<size_t> compressedSize =
      compressJpeg(resolution.width, resolution.height, quality,
                   framebuffer->getHardwareBuffer(), {},
                   compressedThumbnail.size(), compressedThumbnail.data());
  if (!compressedSize.has_value()) {
    ALOGE("%s: Failed to compress jpeg thumbnail", __func__);
    return {};
  }
  compressedThumbnail.resize(compressedSize.value());
  return compressedThumbnail;
}

ndk::ScopedAStatus VirtualCameraRenderThread::renderIntoBlobStreamBuffer(
    const int streamId, const int bufferId, const CameraMetadata& resultMetadata,
    const RequestSettings& requestSettings, sp<Fence> fence) {
  std::shared_ptr<AHardwareBuffer> hwBuffer =
      mSessionContext.fetchHardwareBuffer(streamId, bufferId);
  if (hwBuffer == nullptr) {
    ALOGE("%s: Failed to fetch hardware buffer %d for streamId %d", __func__,
          bufferId, streamId);
    return cameraStatus(Status::INTERNAL_ERROR);
  }

  std::optional<Stream> stream = mSessionContext.getStreamConfig(streamId);
  if (!stream.has_value()) {
    ALOGE("%s, failed to fetch information about stream %d", __func__, streamId);
    return cameraStatus(Status::INTERNAL_ERROR);
  }

  ALOGV("%s: Rendering JPEG with size %d x %d, quality %d", __func__,
        stream->width, stream->height, requestSettings.jpegQuality);

  // Let's create YUV framebuffer and render the surface into this.
  // This will take care about rescaling as well as potential format conversion.
  // The buffer dimensions need to be rounded to nearest multiple of JPEG DCT
  // size, however we pass the viewport corresponding to size of the stream so
  // the image will be only rendered to the area corresponding to the stream
  // size.
  Resolution bufferSize =
      roundTo2DctSize(Resolution(stream->width, stream->height));
  std::shared_ptr<EglFrameBuffer> framebuffer = allocateTemporaryFramebuffer(
      mEglDisplayContext->getEglDisplay(), bufferSize.width, bufferSize.height);
  if (framebuffer == nullptr) {
    ALOGE("Failed to allocate temporary framebuffer for JPEG compression");
    return cameraStatus(Status::INTERNAL_ERROR);
  }

  // Render into temporary framebuffer.
  ndk::ScopedAStatus status = renderIntoEglFramebuffer(
      *framebuffer, /*fence=*/nullptr, Rect(stream->width, stream->height));
  if (!status.isOk()) {
    ALOGE("Failed to render input texture into temporary framebuffer");
    return status;
  }

  PlanesLockGuard planesLock(hwBuffer, AHARDWAREBUFFER_USAGE_CPU_WRITE_OFTEN,
                             fence);
  if (planesLock.getStatus() != OK) {
    ALOGE("Failed to lock hwBuffer planes");
    return cameraStatus(Status::INTERNAL_ERROR);
  }

  std::vector<uint8_t> app1ExifData =
      createExif(Resolution(stream->width, stream->height), resultMetadata,
                 createThumbnail(requestSettings.thumbnailResolution,
                                 requestSettings.thumbnailJpegQuality));

  unsigned long outBufferSize = stream->bufferSize - sizeof(CameraBlob);
  void* outBuffer = (*planesLock).planes[0].data;
  std::optional<size_t> compressedSize = compressJpeg(
      stream->width, stream->height, requestSettings.jpegQuality,
      framebuffer->getHardwareBuffer(), app1ExifData, outBufferSize, outBuffer);

  if (!compressedSize.has_value()) {
    ALOGE("%s: Failed to compress JPEG image", __func__);
    return cameraStatus(Status::INTERNAL_ERROR);
  }

  // Add the transport header at the end of the JPEG output buffer.
  //
  // jpegBlobId must start at byte[buffer_size - sizeof(CameraBlob)],
  // where the buffer_size is the size of gralloc buffer.
  //
  // See
  // hardware/interfaces/camera/device/aidl/android/hardware/camera/device/CameraBlobId.aidl
  // for the full explanation of the following code.
  CameraBlob cameraBlob{
      .blobId = CameraBlobId::JPEG,
      .blobSizeBytes = static_cast<int32_t>(compressedSize.value())};

  // Copy the cameraBlob to the end of the JPEG buffer.
  uint8_t* jpegStreamEndAddress =
      reinterpret_cast<uint8_t*>((*planesLock).planes[0].data) +
      (stream->bufferSize - sizeof(cameraBlob));
  memcpy(jpegStreamEndAddress, &cameraBlob, sizeof(cameraBlob));

  ALOGV("%s: Successfully compressed JPEG image, resulting size %zu B",
        __func__, compressedSize.value());

  return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus VirtualCameraRenderThread::renderIntoImageStreamBuffer(
    int streamId, int bufferId, sp<Fence> fence) {
  ALOGV("%s", __func__);

  const std::chrono::nanoseconds before =
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          std::chrono::steady_clock::now().time_since_epoch());

  // Render test pattern using EGL.
  std::shared_ptr<EglFrameBuffer> framebuffer =
      mSessionContext.fetchOrCreateEglFramebuffer(
          mEglDisplayContext->getEglDisplay(), streamId, bufferId);
  if (framebuffer == nullptr) {
    ALOGE(
        "%s: Failed to get EGL framebuffer corresponding to buffer id "
        "%d for streamId %d",
        __func__, bufferId, streamId);
    return cameraStatus(Status::ILLEGAL_ARGUMENT);
  }

  ndk::ScopedAStatus status = renderIntoEglFramebuffer(*framebuffer, fence);

  const std::chrono::nanoseconds after =
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          std::chrono::steady_clock::now().time_since_epoch());

  ALOGV("Rendering to buffer %d, stream %d took %lld ns", bufferId, streamId,
        after.count() - before.count());

  return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus VirtualCameraRenderThread::renderIntoEglFramebuffer(
    EglFrameBuffer& framebuffer, sp<Fence> fence, std::optional<Rect> viewport) {
  ALOGV("%s", __func__);
  // Wait for fence to clear.
  if (fence != nullptr && fence->isValid()) {
    status_t ret = fence->wait(kAcquireFenceTimeout.count());
    if (ret != 0) {
      ALOGE("Timeout while waiting for the acquire fence for buffer");
      return cameraStatus(Status::INTERNAL_ERROR);
    }
  }

  mEglDisplayContext->makeCurrent();
  framebuffer.beforeDraw();

  Rect viewportRect =
      viewport.value_or(Rect(framebuffer.getWidth(), framebuffer.getHeight()));
  glViewport(viewportRect.left, viewportRect.top, viewportRect.getWidth(),
             viewportRect.getHeight());

  sp<GraphicBuffer> textureBuffer = mEglSurfaceTexture->getCurrentBuffer();
  if (textureBuffer == nullptr) {
    // If there's no current buffer, nothing was written to the surface and
    // texture is not initialized yet. Let's render the framebuffer black
    // instead of rendering the texture.
    glClearColor(0.0f, 0.5f, 0.5f, 0.0f);
    glClear(GL_COLOR_BUFFER_BIT);
  } else {
    const bool renderSuccess =
        isYuvFormat(static_cast<PixelFormat>(textureBuffer->getPixelFormat()))
            ? mEglTextureYuvProgram->draw(
                  mEglSurfaceTexture->getTextureId(),
                  mEglSurfaceTexture->getTransformMatrix())
            : mEglTextureRgbProgram->draw(
                  mEglSurfaceTexture->getTextureId(),
                  mEglSurfaceTexture->getTransformMatrix());
    if (!renderSuccess) {
      ALOGE("%s: Failed to render texture", __func__);
      return cameraStatus(Status::INTERNAL_ERROR);
    }
  }
  framebuffer.afterDraw();

  return ndk::ScopedAStatus::ok();
}

}  // namespace virtualcamera
}  // namespace companion
}  // namespace android
