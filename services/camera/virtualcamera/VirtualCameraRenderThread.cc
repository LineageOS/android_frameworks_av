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

#define LOG_TAG "VirtualCameraRenderThread"
#include "VirtualCameraRenderThread.h"

#include <chrono>
#include <cstddef>
#include <future>
#include <memory>
#include <mutex>
#include <thread>

#include "GLES/gl.h"
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
#include "util/EglFramebuffer.h"
#include "util/JpegUtil.h"
#include "util/MetadataBuilder.h"
#include "util/TestPatternHelper.h"
#include "util/Util.h"
#include "utils/Errors.h"

namespace android {
namespace companion {
namespace virtualcamera {

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

namespace {

using namespace std::chrono_literals;

static constexpr std::chrono::milliseconds kAcquireFenceTimeout = 500ms;

CameraMetadata createCaptureResultMetadata(
    const std::chrono::nanoseconds timestamp) {
  std::unique_ptr<CameraMetadata> metadata =
      MetadataBuilder().setSensorTimestamp(timestamp).build();
  if (metadata == nullptr) {
    ALOGE("%s: Failed to build capture result metadata", __func__);
    return CameraMetadata();
  }
  return std::move(*metadata);
}

NotifyMsg createShutterNotifyMsg(int frameNumber,
                                 std::chrono::nanoseconds timestamp) {
  NotifyMsg msg;
  msg.set<NotifyMsg::Tag::shutter>(ShutterMsg{
      .frameNumber = frameNumber,
      .timestamp = timestamp.count(),
  });
  return msg;
}

NotifyMsg createBufferErrorNotifyMsg(int frameNumber, int streamId) {
  NotifyMsg msg;
  msg.set<NotifyMsg::Tag::error>(ErrorMsg{.frameNumber = frameNumber,
                                          .errorStreamId = streamId,
                                          .errorCode = ErrorCode::ERROR_BUFFER});
  return msg;
}

NotifyMsg createRequestErrorNotifyMsg(int frameNumber) {
  NotifyMsg msg;
  msg.set<NotifyMsg::Tag::error>(ErrorMsg{
      .frameNumber = frameNumber,
      // errorStreamId needs to be set to -1 for ERROR_REQUEST
      // (not tied to specific stream).
      .errorStreamId = -1,
      .errorCode = ErrorCode::ERROR_REQUEST});
  return msg;
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
    VirtualCameraSessionContext& sessionContext, const int mWidth,
    const int mHeight,
    std::shared_ptr<ICameraDeviceCallback> cameraDeviceCallback, bool testMode)
    : mCameraDeviceCallback(cameraDeviceCallback),
      mInputSurfaceWidth(mWidth),
      mInputSurfaceHeight(mHeight),
      mTestMode(testMode),
      mSessionContext(sessionContext) {
}

VirtualCameraRenderThread::~VirtualCameraRenderThread() {
  stop();
  if (mThread.joinable()) {
    mThread.join();
  }
}

ProcessCaptureRequestTask::ProcessCaptureRequestTask(
    int frameNumber, const std::vector<CaptureRequestBuffer>& requestBuffers)
    : mFrameNumber(frameNumber), mBuffers(requestBuffers) {
}

int ProcessCaptureRequestTask::getFrameNumber() const {
  return mFrameNumber;
}

const std::vector<CaptureRequestBuffer>& ProcessCaptureRequestTask::getBuffers()
    const {
  return mBuffers;
}

void VirtualCameraRenderThread::enqueueTask(
    std::unique_ptr<ProcessCaptureRequestTask> task) {
  std::lock_guard<std::mutex> lock(mLock);
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
  return mInputSurfacePromise.get_future().get();
}

std::unique_ptr<ProcessCaptureRequestTask>
VirtualCameraRenderThread::dequeueTask() {
  std::unique_lock<std::mutex> lock(mLock);
  // Clang's thread safety analysis doesn't perform alias analysis,
  // so it doesn't support moveable std::unique_lock.
  //
  // Lock assertion below is basically explicit declaration that
  // the lock is held in this scope, which is true, since it's only
  // released during waiting inside mCondVar.wait calls.
  ScopedLockAssertion lockAssertion(mLock);

  mCondVar.wait(lock, [this]() REQUIRES(mLock) {
    return mPendingExit || !mQueue.empty();
  });
  if (mPendingExit) {
    return nullptr;
  }
  std::unique_ptr<ProcessCaptureRequestTask> task = std::move(mQueue.front());
  mQueue.pop_front();
  return task;
}

void VirtualCameraRenderThread::threadLoop() {
  ALOGV("Render thread starting");

  mEglDisplayContext = std::make_unique<EglDisplayContext>();
  mEglTextureProgram = std::make_unique<EglTextureProgram>();
  mEglSurfaceTexture = std::make_unique<EglSurfaceTexture>(mInputSurfaceWidth,
                                                           mInputSurfaceHeight);
  mInputSurfacePromise.set_value(mEglSurfaceTexture->getSurface());

  while (std::unique_ptr<ProcessCaptureRequestTask> task = dequeueTask()) {
    processCaptureRequest(*task);
  }

  ALOGV("Render thread exiting");
}

void VirtualCameraRenderThread::processCaptureRequest(
    const ProcessCaptureRequestTask& request) {
  const std::chrono::nanoseconds timestamp =
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          std::chrono::steady_clock::now().time_since_epoch());

  CaptureResult captureResult;
  captureResult.fmqResultSize = 0;
  captureResult.frameNumber = request.getFrameNumber();
  // Partial result needs to be set to 1 when metadata are present.
  captureResult.partialResult = 1;
  captureResult.inputBuffer.streamId = -1;
  captureResult.physicalCameraMetadata.resize(0);
  captureResult.result = createCaptureResultMetadata(timestamp);

  const std::vector<CaptureRequestBuffer>& buffers = request.getBuffers();
  captureResult.outputBuffers.resize(buffers.size());

  if (mTestMode) {
    // In test mode let's just render something to the Surface ourselves.
    renderTestPatternYCbCr420(mEglSurfaceTexture->getSurface(),
                              request.getFrameNumber());
  }

  mEglSurfaceTexture->updateTexture();

  for (int i = 0; i < buffers.size(); ++i) {
    const CaptureRequestBuffer& reqBuffer = buffers[i];
    StreamBuffer& resBuffer = captureResult.outputBuffers[i];
    resBuffer.streamId = reqBuffer.getStreamId();
    resBuffer.bufferId = reqBuffer.getBufferId();
    resBuffer.status = BufferStatus::OK;

    const std::optional<Stream> streamConfig =
        mSessionContext.getStreamConfig(reqBuffer.getStreamId());

    if (!streamConfig.has_value()) {
      resBuffer.status = BufferStatus::ERROR;
      continue;
    }

    auto status = streamConfig->format == PixelFormat::BLOB
                      ? renderIntoBlobStreamBuffer(reqBuffer.getStreamId(),
                                                   reqBuffer.getBufferId(),
                                                   reqBuffer.getFence())
                      : renderIntoImageStreamBuffer(reqBuffer.getStreamId(),
                                                    reqBuffer.getBufferId(),
                                                    reqBuffer.getFence());
    if (!status.isOk()) {
      resBuffer.status = BufferStatus::ERROR;
    }
  }

  std::vector<NotifyMsg> notifyMsg{
      createShutterNotifyMsg(request.getFrameNumber(), timestamp)};
  for (const StreamBuffer& resBuffer : captureResult.outputBuffers) {
    if (resBuffer.status != BufferStatus::OK) {
      notifyMsg.push_back(createBufferErrorNotifyMsg(request.getFrameNumber(),
                                                     resBuffer.streamId));
    }
  }

  auto status = mCameraDeviceCallback->notify(notifyMsg);
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
    return;
  }

  ALOGD("%s: Successfully called processCaptureResult", __func__);
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

ndk::ScopedAStatus VirtualCameraRenderThread::renderIntoBlobStreamBuffer(
    const int streamId, const int bufferId, sp<Fence> fence) {
  ALOGV("%s", __func__);
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

  AHardwareBuffer_Planes planes_info;

  int32_t rawFence = fence != nullptr ? fence->get() : -1;
  int result = AHardwareBuffer_lockPlanes(hwBuffer.get(),
                                          AHARDWAREBUFFER_USAGE_CPU_READ_RARELY,
                                          rawFence, nullptr, &planes_info);
  if (result != OK) {
    ALOGE("%s: Failed to lock planes for BLOB buffer: %d", __func__, result);
    return cameraStatus(Status::INTERNAL_ERROR);
  }

  sp<GraphicBuffer> gBuffer = mEglSurfaceTexture->getCurrentBuffer();
  bool compressionSuccess = true;
  if (gBuffer != nullptr) {
    android_ycbcr ycbcr;
    status_t status =
        gBuffer->lockYCbCr(AHARDWAREBUFFER_USAGE_CPU_READ_OFTEN, &ycbcr);
    ALOGV("Locked buffers");
    if (status != NO_ERROR) {
      AHardwareBuffer_unlock(hwBuffer.get(), nullptr);
      ALOGE("%s: Failed to lock graphic buffer: %d", __func__, status);
      return cameraStatus(Status::INTERNAL_ERROR);
    }

    compressionSuccess =
        compressJpeg(gBuffer->getWidth(), gBuffer->getHeight(), ycbcr,
                     stream->bufferSize, planes_info.planes[0].data);

    status_t res = gBuffer->unlock();
    if (res != NO_ERROR) {
      ALOGE("Failed to unlock graphic buffer: %d", res);
    }
  } else {
    compressionSuccess =
        compressBlackJpeg(stream->width, stream->height, stream->bufferSize,
                          planes_info.planes[0].data);
  }
  AHardwareBuffer_unlock(hwBuffer.get(), nullptr);
  ALOGV("Unlocked buffers");
  return compressionSuccess ? ndk::ScopedAStatus::ok()
                            : cameraStatus(Status::INTERNAL_ERROR);
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

  // Wait for fence to clear.
  if (fence != nullptr && fence->isValid()) {
    status_t ret = fence->wait(kAcquireFenceTimeout.count());
    if (ret != 0) {
      ALOGE(
          "Timeout while waiting for the acquire fence for buffer %d"
          " for streamId %d",
          bufferId, streamId);
      return cameraStatus(Status::INTERNAL_ERROR);
    }
  }

  mEglDisplayContext->makeCurrent();
  framebuffer->beforeDraw();

  if (mEglSurfaceTexture->getCurrentBuffer() == nullptr) {
    // If there's no current buffer, nothing was written to the surface and
    // texture is not initialized yet. Let's render the framebuffer black
    // instead of rendering the texture.
    glClearColor(0.0f, 0.5f, 0.5f, 0.0f);
    glClear(GL_COLOR_BUFFER_BIT);
  } else {
    mEglTextureProgram->draw(mEglSurfaceTexture->updateTexture());
  }
  framebuffer->afterDraw();

  const std::chrono::nanoseconds after =
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          std::chrono::steady_clock::now().time_since_epoch());

  ALOGV("Rendering to buffer %d, stream %d took %lld ns", bufferId, streamId,
        after.count() - before.count());

  return ndk::ScopedAStatus::ok();
}

}  // namespace virtualcamera
}  // namespace companion
}  // namespace android
