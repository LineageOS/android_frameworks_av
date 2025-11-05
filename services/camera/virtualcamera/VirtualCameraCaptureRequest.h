/*
 * Copyright (C) 2024 The Android Open Source Project
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
#ifndef ANDROID_COMPANION_VIRTUALCAMERA_VIRTUALCAMERACAPTUREREQUEST_H
#define ANDROID_COMPANION_VIRTUALCAMERA_VIRTUALCAMERACAPTUREREQUEST_H

#include <optional>

#include "VirtualCameraDevice.h"
#include "ui/Fence.h"
#include "util/Util.h"

namespace android {
namespace companion {
namespace virtualcamera {

// Struct used to pass request settings in the different part of
// the virtual camera system.
struct RequestSettings {
  // JPEG_QUALITY metadata
  int jpegQuality = VirtualCameraDevice::kDefaultJpegQuality;

  // JPEG_ORIENTATION metadata
  int jpegOrientation = VirtualCameraDevice::kDefaultJpegOrientation;

  // JPEG_THUMBNAIL_SIZE metadata
  Resolution thumbnailResolution = Resolution(0, 0);

  // JPEG_THUMBNAIL_QUALITY metadata
  int thumbnailJpegQuality = VirtualCameraDevice::kDefaultJpegQuality;

  // ANDROID_CONTROL_AE_TARGET_FPS_RANGE metadata
  std::optional<FpsRange> fpsRange;

  // CONTROL_CAPTURE_INTENT metadata
  camera_metadata_enum_android_control_capture_intent_t captureIntent =
      VirtualCameraDevice::kDefaultCaptureIntent;

  // JPEG_GPS_LOCATION metadata
  std::optional<GpsCoordinates> gpsCoordinates;

  // CONTROL_AE_PRECAPTURE_TRIGGER metadata
  std::optional<camera_metadata_enum_android_control_ae_precapture_trigger>
      aePrecaptureTrigger;
};

// Represents single output buffer of capture request.
class CaptureRequestBuffer {
 public:
  CaptureRequestBuffer(int streamId, int bufferId, sp<Fence> fence = nullptr)
      : mStreamId(streamId), mBufferId(bufferId), mFence(fence) {
  }

  int getStreamId() const {
    return mStreamId;
  }
  int getBufferId() const {
    return mBufferId;
  }
  sp<Fence> getFence() const {
    return mFence;
  }

 private:
  const int mStreamId;
  const int mBufferId;
  const sp<Fence> mFence;
};

}  // namespace virtualcamera
}  // namespace companion
}  // namespace android

#endif  // ANDROID_COMPANION_VIRTUALCAMERA_VIRTUALCAMERACAPTUREREQUEST_H
