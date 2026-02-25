/*
 * Copyright (C) 2025 The Android Open Source Project
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
#define LOG_TAG "VirtualCameraImagePassthroughHandler"

#include "VirtualCameraImagePassthroughHandler.h"

#include <aidl/android/hardware/camera/device/CameraBlob.h>
#include <aidl/android/hardware/camera/device/CameraBlobId.h>
#include <android/hardware_buffer.h>
#include <gui/Surface.h>
#include <media/NdkImageReader.h>
#include <media/NdkMediaError.h>
#include <sys/select.h>
#include <unistd.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>

#include "VirtualCameraCaptureRequest.h"
#include "VirtualCameraSessionContext.h"
#include "aidl/android/companion/virtualcamera/Format.h"
#include "aidl/android/hardware/camera/device/CaptureResult.h"
#include "aidl/android/hardware/camera/device/Stream.h"
#include "android/binder_auto_utils.h"
#include "util/JpegUtil.h"
#include "util/Util.h"
#include "utils/Errors.h"

namespace android {
namespace companion {
namespace virtualcamera {
namespace {

using ::aidl::android::companion::virtualcamera::Format;
using ::aidl::android::hardware::camera::common::Status;
using ::aidl::android::hardware::camera::device::CameraBlob;
using ::aidl::android::hardware::camera::device::Stream;

using ScopedAImageReader =
    std::unique_ptr<AImageReader,
                    CustomDeleter<AImageReader, AImageReader_delete>>;
using ScopedAImage =
    std::unique_ptr<AImage, CustomDeleter<AImage, AImage_delete>>;

constexpr int kHardwareBufferUsageFlags = AHARDWAREBUFFER_USAGE_CPU_READ_OFTEN |
                                          AHARDWAREBUFFER_USAGE_CPU_WRITE_OFTEN;
constexpr int kImageFrameCount = 10;

const int kSurfaceSizeWidth = kMaxJpegSize + sizeof(CameraBlob);
constexpr int kSurfaceSizeHeight = 1;

void onImageReceived(void* context, AImageReader* /*reader*/) {
  if (!context) {
    ALOGE("%s: null context in onImageReceived() callback", __func__);
    return;
  }

  VirtualCameraImagePassthroughHandler* imageConsumer =
      reinterpret_cast<VirtualCameraImagePassthroughHandler*>(context);
  imageConsumer->onFrameAvailable();
}
}  // namespace

std::unique_ptr<VirtualCameraImagePassthroughHandler>
VirtualCameraImagePassthroughHandler::create(
    VirtualCameraSessionContext& sessionContext, Format imageFormat,
    std::function<void(void)> frameReadyCallback) {
  ALOGV("%s: allocating ImageReader, width=%d, height=%d, frame_count=%d",
        __func__, kSurfaceSizeWidth, kSurfaceSizeHeight, kImageFrameCount);

  AImageReader* reader = nullptr;
  media_status_t ret = AImageReader_newWithUsage(
      kSurfaceSizeWidth, kSurfaceSizeHeight,
      static_cast<AIMAGE_FORMATS>(imageFormat), kHardwareBufferUsageFlags,
      kImageFrameCount, &reader);

  if (ret != AMEDIA_OK || !reader) {
    ALOGE("%s: Fail to start RenderThread because cannot create an ImageReader",
          __func__);
    return nullptr;
  }

  ScopedAImageReader scopedImageReader{reader};

  ANativeWindow* window = nullptr;
  if (AImageReader_getWindow(reader, &window) != AMEDIA_OK) {
    ALOGE("%s: Fail to get the native window of the ImageReader", __func__);
    return nullptr;
  }

  sp<Surface> inputSurface = Surface::from(window);

  auto imageConsumer = std::make_unique<VirtualCameraImagePassthroughHandler>(
      sessionContext, imageFormat, std::move(frameReadyCallback),
      std::move(inputSurface), std::move(scopedImageReader));

  AImageReader_ImageListener imagelistener{
      .context = imageConsumer.get(),
      .onImageAvailable = onImageReceived,
  };

  if (AImageReader_setImageListener(reader, &imagelistener) != AMEDIA_OK) {
    ALOGE("%s: Failed to set the image listener", __func__);
    return nullptr;
  }

  return imageConsumer;
}

VirtualCameraImagePassthroughHandler::VirtualCameraImagePassthroughHandler(
    VirtualCameraSessionContext& sessionContext, Format imageFormat,
    std::function<void(void)> frameReadyCallback, sp<Surface> inputSurface,
    std::unique_ptr<AImageReader, CustomDeleter<AImageReader, AImageReader_delete>>
        imageReader)
    : mSessionContext{sessionContext},
      mImageFormat{imageFormat},
      mOnFrameAvailable{std::move(frameReadyCallback)},
      mFrameAvailablePromiseSignalled{false},
      mIsFirstFrameDrawn{false},
      mInputSurface{std::move(inputSurface)},
      mImageReader{std::move(imageReader)} {
  resetFrameAvailableSignalingMechanism();
}

VirtualCameraImagePassthroughHandler::~VirtualCameraImagePassthroughHandler() {
  // Clear current ImageReader callback. This ensures that the internal
  // ImageReader thread cannot access VirtualCameraImagePassthroughHandler
  // member variables during the destruction sequence.
  AImageReader_ImageListener imagelistener{
      .context = nullptr,
      .onImageAvailable = nullptr,
  };

  if (AImageReader_setImageListener(mImageReader.get(), &imagelistener) !=
      AMEDIA_OK) {
    ALOGE("%s: Failed to clear image listener", __func__);
  }

  mImageReader.reset();

  {
    std::lock_guard<std::mutex> criticalSection{mFrameAvailableCallbackMutex};

    // Signal mFrameAvailablePromise but indicate that a new frame has not
    // arrived. It is possible that a call to waitForFrame() is currently
    // blocked and fulfilling the promise will allow that routine to make
    // progress.
    if (!mFrameAvailablePromiseSignalled) {
      mFrameAvailablePromise->set_value(false);
    }

    mFrameAvailableFuture.reset();
    mFrameAvailablePromise.reset();
  }
}

bool VirtualCameraImagePassthroughHandler::waitForInputFrame(
    const std::chrono::nanoseconds timeoutNs) {
  // Attempt to obtain image in non-blocking mode
  AImage* image = nullptr;
  int syncFd = 0;
  media_status_t acquireImageResult =
      AImageReader_acquireLatestImageAsync(mImageReader.get(), &image, &syncFd);

  if (acquireImageResult == AMEDIA_OK) {
    // A sync fd of -1 indicates frame is available now
    if (syncFd == -1) {
      ALOGV("%s: Received new image", __func__);
      mCurrentImage = ScopedAImage{image};
      mIsFirstFrameDrawn = true;

      // New frame has been acquired. Reset now spent promise/future
      // to facilitate signaling of next frame
      resetFrameAvailableSignalingMechanism();
      return true;

    } else {
      // Ignore sync fd if it refers to valid file descriptor. This is because
      // we rely on the promise/future signaling mechanism rather than file
      // descriptors. The Android graphics system makes valid sync fds available
      // only under certain conditions, specifically those involving HW
      // rendering pathways. The Virtual Camera module must handle cases in
      // which the CPU is the producer, therefore we ignore the file descriptor
      // approach altogether and rely on an alternative signaling mechanism that
      // works for both HW- and SW-based producer paradigms.
      ALOGW("%s: Unexpectedly received valid sync fd (%d). Discarding...",
            __func__, syncFd);
      close(syncFd);
    }

  } else if (acquireImageResult != AMEDIA_IMGREADER_NO_BUFFER_AVAILABLE) {
    ALOGE("%s: failure in AImageReader_acquireLatestImageAsync(): error=%d",
          __func__, (int)acquireImageResult);
    return false;
  }

  if (mFrameAvailableFuture->wait_for(timeoutNs) != std::future_status::ready) {
    ALOGE("%s: timed out after %llu ns waiting for frame arrival", __func__,
          timeoutNs.count());
    resetFrameAvailableSignalingMechanism();
    return false;
  }

  bool frameAvailable = mFrameAvailableFuture->get();
  resetFrameAvailableSignalingMechanism();
  return frameAvailable;
}

void VirtualCameraImagePassthroughHandler::interruptWait() {
  std::lock_guard<std::mutex> criticalSection{mFrameAvailableCallbackMutex};
  if (!mFrameAvailablePromiseSignalled && mFrameAvailablePromise != nullptr) {
    mFrameAvailablePromiseSignalled = true;
    mFrameAvailablePromise->set_value(false);
  }
}

void VirtualCameraImagePassthroughHandler::updateTexture() {
  // This function is generally called after the surface "on frame" callback has
  // been triggered, so we consume the new frame immediately
  waitForInputFrame(std::chrono::nanoseconds{0});
}

std::chrono::nanoseconds VirtualCameraImagePassthroughHandler::getTimestamp() {
  int64_t timestampNs;
  if (AImage_getTimestamp(mCurrentImage.get(), &timestampNs) != AMEDIA_OK) {
    ALOGE("%s: failure during AImage_getTimestamp()", __func__);
    return std::chrono::nanoseconds{0};
  }

  return std::chrono::nanoseconds{timestampNs};
}

bool VirtualCameraImagePassthroughHandler::isFirstFrameDrawn() {
  return mIsFirstFrameDrawn;
}

sp<Surface> VirtualCameraImagePassthroughHandler::getInputSurface() {
  return mInputSurface;
}

ndk::ScopedAStatus VirtualCameraImagePassthroughHandler::fillOutputBuffer(
    const RequestSettings& /*requestSettings*/,
    const CaptureRequestBuffer& requestBuffer, const Stream& halStreamConfig,
    ::aidl::android::hardware::camera::device::CaptureResult& /*captureResult*/) {
  const int streamId = requestBuffer.getStreamId();
  const int bufferId = requestBuffer.getBufferId();

  std::shared_ptr<AHardwareBuffer> hwBuffer =
      mSessionContext.fetchHardwareBuffer(streamId, bufferId);
  if (hwBuffer == nullptr) {
    ALOGE("%s: Failed to fetch hardware buffer %d for streamId %d", __func__,
          bufferId, streamId);
    return cameraStatus(Status::INTERNAL_ERROR);
  }

  PlanesLockGuard planesLock(hwBuffer, AHARDWAREBUFFER_USAGE_CPU_WRITE_OFTEN,
                             requestBuffer.getFence());
  if (planesLock.getStatus() != OK) {
    ALOGE("%s: Failed to lock hwBuffer planes", __func__);
    return cameraStatus(Status::INTERNAL_ERROR);
  }

  // Avoid overwriting the CameraBlob footer, which may be placed at the very
  // end of the BLOB buffer.
  //
  // See
  // hardware/interfaces/camera/device/aidl/android/hardware/camera/device/CameraBlobId.aidl
  int32_t outBufferSize = halStreamConfig.bufferSize - sizeof(CameraBlob);
  uint8_t* outBuffer = reinterpret_cast<uint8_t*>((*planesLock).planes[0].data);

  int planeIndex = 0;
  uint8_t* inputBuffer = nullptr;
  int32_t inputBufferSize = 0;
  if (AImage_getPlaneData(mCurrentImage.get(), planeIndex, &inputBuffer,
                          &inputBufferSize) != AMEDIA_OK) {
    ALOGE("%s: Failure during AImage_getPlaneData()", __func__);
    return cameraStatus(Status::INTERNAL_ERROR);
  }

  if (outBufferSize < inputBufferSize) {
    ALOGW(
        "%s: BLOB input consumed from surface is larger (%d bytes) than output "
        "buffer size (%d bytes)",
        __func__, inputBufferSize, outBufferSize);
  }

  size_t bufferSize =
      (outBufferSize < inputBufferSize) ? outBufferSize : inputBufferSize;

  // Write BLOB payload to beginning of output buffer
  memcpy(outBuffer, inputBuffer, bufferSize);

  // TODO(b/457285222): add BLOB footer to output buffer once ByteBuffer bug is
  // resolved. Note that the footer is an optional optimization so it is
  // acceptable to omit.

  ALOGV("%s: Successfully transferred BLOB payload, format=0x%x, size=%d",
        __func__, mImageFormat, inputBufferSize);

  return ndk::ScopedAStatus::ok();
}

void VirtualCameraImagePassthroughHandler::onFrameAvailable() {
  {
    std::lock_guard<std::mutex> criticalSection{mFrameAvailableCallbackMutex};

    // Signal the future corresponding to mFrameAvailablePromise to indicate
    // that new frame has arrived. It is possible that a call to waitForFrame()
    // is in progress and is currently blocked waiting for this signal.
    // Fulfilling mFrameAvailablePromise unblocks waitForFrame() and allows
    // it to make progress. Only issue a new signal if the current instance of
    // mFrameAvailablePromise has not already been fulfilled.
    if (!mFrameAvailablePromiseSignalled) {
      mFrameAvailablePromiseSignalled = true;
      mFrameAvailablePromise->set_value(true);
    }
  }

  mOnFrameAvailable();
}

void VirtualCameraImagePassthroughHandler::resetFrameAvailableSignalingMechanism() {
  std::lock_guard<std::mutex> criticalSection{mFrameAvailableCallbackMutex};

  mFrameAvailablePromiseSignalled = false;
  mFrameAvailablePromise = std::make_unique<std::promise<bool>>();
  mFrameAvailableFuture = std::make_unique<std::future<bool>>();
  *mFrameAvailableFuture = mFrameAvailablePromise->get_future();
}

}  // namespace virtualcamera
}  // namespace companion
}  // namespace android
