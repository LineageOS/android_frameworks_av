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
#define LOG_TAG "VirtualCameraImageTransformingHandler"

#include "VirtualCameraImageTransformingHandler.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

#include "Exif.h"
#include "GLES/gl.h"
#include "VirtualCameraCaptureRequest.h"
#include "VirtualCameraSessionContext.h"
#include "aidl/android/hardware/camera/device/CameraBlob.h"
#include "aidl/android/hardware/camera/device/CameraBlobId.h"
#include "aidl/android/hardware/camera/device/CameraMetadata.h"
#include "android/binder_auto_utils.h"
#include "ui/Rect.h"
#include "util/EglDisplayContext.h"
#include "util/EglFramebuffer.h"
#include "util/EglProgram.h"
#include "util/EglSurfaceTexture.h"
#include "util/JpegUtil.h"
#include "util/Util.h"
#include "utils/Errors.h"

namespace android {
namespace companion {
namespace virtualcamera {

using ::aidl::android::hardware::camera::common::Status;
using ::aidl::android::hardware::camera::device::CameraBlob;
using ::aidl::android::hardware::camera::device::CameraBlobId;
using ::aidl::android::hardware::camera::device::CameraMetadata;
using ::aidl::android::hardware::camera::device::CaptureResult;
using ::aidl::android::hardware::camera::device::ErrorCode;
using ::aidl::android::hardware::camera::device::ErrorMsg;
using ::aidl::android::hardware::camera::device::Stream;
using ::aidl::android::hardware::camera::device::StreamBuffer;
using ::aidl::android::hardware::graphics::common::PixelFormat;
using ::android::hardware::camera::common::helper::ExifUtils;

namespace {

using namespace std::chrono_literals;

static constexpr std::chrono::milliseconds kAcquireFenceTimeout = 500ms;
static constexpr size_t kJpegThumbnailBufferSize = 32 * 1024;  // 32 KiB

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

std::vector<uint8_t> createExif(
    Resolution imageSize, const CameraMetadata resultMetadata,
    const std::vector<uint8_t>& compressedThumbnail = {}) {
  std::unique_ptr<ExifUtils> exifUtils(ExifUtils::create());
  exifUtils->initialize();

  // Make a copy of the metadata in order to convert it the HAL metadata
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

}  // namespace

VirtualCameraImageTransformingHandler::VirtualCameraImageTransformingHandler(
    VirtualCameraSessionContext& sessionContext, Resolution inputSurfaceSize,
    std::function<void(void)> frameReadyCallback)
    : mSessionContext{sessionContext} {
  mEglDisplayContext = std::make_unique<EglDisplayContext>();
  mEglTextureYuvProgram =
      std::make_unique<EglTextureProgram>(EglTextureProgram::TextureFormat::YUV);
  mEglTextureRgbProgram = std::make_unique<EglTextureProgram>(
      EglTextureProgram::TextureFormat::RGBA);
  mEglSurfaceTexture = std::make_unique<EglSurfaceTexture>(
      inputSurfaceSize.width, inputSurfaceSize.height);
  mEglSurfaceTexture->setFrameAvailableListener(
      [frameReadyCallback]() { frameReadyCallback(); });
}

VirtualCameraImageTransformingHandler::~VirtualCameraImageTransformingHandler() {
}

bool VirtualCameraImageTransformingHandler::waitForInputFrame(
    const std::chrono::nanoseconds timeout) {
  return mEglSurfaceTexture->waitForNextFrame(timeout);
}

void VirtualCameraImageTransformingHandler::interruptWait() {
  mEglSurfaceTexture->interruptWait();
}

void VirtualCameraImageTransformingHandler::updateTexture() {
  mEglSurfaceTexture->updateTexture();
}

std::chrono::nanoseconds VirtualCameraImageTransformingHandler::getTimestamp() {
  return mEglSurfaceTexture->getTimestamp();
}

bool VirtualCameraImageTransformingHandler::isFirstFrameDrawn() {
  return mEglSurfaceTexture->isFirstFrameDrawn();
}

sp<Surface> VirtualCameraImageTransformingHandler::getInputSurface() {
  return mEglSurfaceTexture->getSurface();
}

ndk::ScopedAStatus VirtualCameraImageTransformingHandler::fillOutputBuffer(
    const RequestSettings& requestSettings,
    const CaptureRequestBuffer& requestBuffer, const Stream& halStreamConfig,
    ::aidl::android::hardware::camera::device::CaptureResult& captureResult) {
  return (halStreamConfig.format == PixelFormat::BLOB)
             ? renderIntoBlobStreamBuffer(requestSettings, requestBuffer,
                                          captureResult)
             : renderIntoImageStreamBuffer(requestBuffer);
}

std::vector<uint8_t> VirtualCameraImageTransformingHandler::createThumbnail(
    Resolution resolution, int quality) {
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

  // TODO(b/324383963) Add support for letterboxing if the thumbnail sizes
  // doesn't correspond to input texture aspect ratio.
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

ndk::ScopedAStatus
VirtualCameraImageTransformingHandler::renderIntoBlobStreamBuffer(
    const RequestSettings& requestSettings,
    const CaptureRequestBuffer& requestBuffer,
    ::aidl::android::hardware::camera::device::CaptureResult& captureResult) {
  const int streamId = requestBuffer.getStreamId();
  const int bufferId = requestBuffer.getBufferId();

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
                             requestBuffer.getFence());
  if (planesLock.getStatus() != OK) {
    ALOGE("Failed to lock hwBuffer planes");
    return cameraStatus(Status::INTERNAL_ERROR);
  }

  std::vector<uint8_t> app1ExifData = createExif(
      Resolution(stream->width, stream->height), captureResult.result,
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

// Render current image to the YCbCr buffer.
// If fence is specified, this function will block until the fence is cleared
// before writing to the buffer.
// Always called on render thread.
ndk::ScopedAStatus
VirtualCameraImageTransformingHandler::renderIntoImageStreamBuffer(
    const CaptureRequestBuffer& requestBuffer) {
  const int streamId = requestBuffer.getStreamId();
  const int bufferId = requestBuffer.getBufferId();

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

  ndk::ScopedAStatus status =
      renderIntoEglFramebuffer(*framebuffer, requestBuffer.getFence());

  const std::chrono::nanoseconds after =
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          std::chrono::steady_clock::now().time_since_epoch());

  ALOGV("Rendering to buffer %d, stream %d took %lld ns", bufferId, streamId,
        after.count() - before.count());

  return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus VirtualCameraImageTransformingHandler::renderIntoEglFramebuffer(
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
