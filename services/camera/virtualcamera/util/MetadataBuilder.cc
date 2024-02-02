/*
 * Copyright 2023 The Android Open Source Project
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
#define LOG_TAG "MetadataBuilder"

#include "MetadataBuilder.h"

#include <algorithm>
#include <cstdint>
#include <iterator>
#include <memory>
#include <utility>
#include <variant>
#include <vector>

#include "CameraMetadata.h"
#include "aidl/android/hardware/camera/device/CameraMetadata.h"
#include "log/log.h"
#include "system/camera_metadata.h"
#include "utils/Errors.h"

namespace android {
namespace companion {
namespace virtualcamera {

namespace {

using ::android::hardware::camera::common::helper::CameraMetadata;

template <typename To, typename From>
std::vector<To> convertTo(const std::vector<From>& from) {
  std::vector<To> to;
  to.reserve(from.size());
  std::transform(from.begin(), from.end(), std::back_inserter(to),
                 [](const From& x) { return static_cast<To>(x); });
  return to;
}

}  // namespace

MetadataBuilder& MetadataBuilder::setSupportedHardwareLevel(
    camera_metadata_enum_android_info_supported_hardware_level_t hwLevel) {
  mEntryMap[ANDROID_INFO_SUPPORTED_HARDWARE_LEVEL] =
      std::vector<uint8_t>({static_cast<uint8_t>(hwLevel)});
  return *this;
}

MetadataBuilder& MetadataBuilder::setFlashAvailable(bool flashAvailable) {
  const uint8_t metadataVal = flashAvailable
                                  ? ANDROID_FLASH_INFO_AVAILABLE_TRUE
                                  : ANDROID_FLASH_INFO_AVAILABLE_FALSE;
  mEntryMap[ANDROID_FLASH_INFO_AVAILABLE] = std::vector<uint8_t>({metadataVal});
  return *this;
}

MetadataBuilder& MetadataBuilder::setLensFacing(
    camera_metadata_enum_android_lens_facing lensFacing) {
  mEntryMap[ANDROID_LENS_FACING] =
      std::vector<uint8_t>({static_cast<uint8_t>(lensFacing)});
  return *this;
}

MetadataBuilder& MetadataBuilder::setSensorReadoutTimestamp(
    const camera_metadata_enum_android_sensor_readout_timestamp_t
        sensorReadoutTimestamp) {
  mEntryMap[ANDROID_SENSOR_READOUT_TIMESTAMP] =
      std::vector<uint8_t>({static_cast<uint8_t>(sensorReadoutTimestamp)});
  return *this;
}

MetadataBuilder& MetadataBuilder::setFocalLength(float focalLength) {
  std::vector<float> focalLengths({focalLength});
  mEntryMap[ANDROID_LENS_FOCAL_LENGTH] = focalLengths;
  mEntryMap[ANDROID_LENS_INFO_AVAILABLE_FOCAL_LENGTHS] = focalLengths;
  return *this;
}

MetadataBuilder& MetadataBuilder::setSensorOrientation(int32_t sensorOrientation) {
  mEntryMap[ANDROID_SENSOR_ORIENTATION] =
      std::vector<int32_t>({sensorOrientation});
  return *this;
}

MetadataBuilder& MetadataBuilder::setSensorTimestamp(
    std::chrono::nanoseconds timestamp) {
  mEntryMap[ANDROID_SENSOR_TIMESTAMP] =
      std::vector<int64_t>({timestamp.count()});
  return *this;
}

MetadataBuilder& MetadataBuilder::setAvailableFaceDetectModes(
    const std::vector<camera_metadata_enum_android_statistics_face_detect_mode_t>&
        faceDetectModes) {
  mEntryMap[ANDROID_STATISTICS_INFO_AVAILABLE_FACE_DETECT_MODES] =
      convertTo<uint8_t>(faceDetectModes);
  return *this;
}

MetadataBuilder& MetadataBuilder::setControlAvailableModes(
    const std::vector<camera_metadata_enum_android_control_mode_t>&
        availableModes) {
  mEntryMap[ANDROID_CONTROL_AVAILABLE_MODES] =
      convertTo<uint8_t>(availableModes);
  return *this;
}

MetadataBuilder& MetadataBuilder::setControlAvailableSceneModes(
    const std::vector<camera_metadata_enum_android_control_scene_mode>&
        availableSceneModes) {
  mEntryMap[ANDROID_CONTROL_AVAILABLE_SCENE_MODES] =
      convertTo<uint8_t>(availableSceneModes);
  return *this;
}

MetadataBuilder& MetadataBuilder::setControlAvailableEffects(
    const std::vector<camera_metadata_enum_android_control_effect_mode>&
        availableEffects) {
  mEntryMap[ANDROID_CONTROL_AVAILABLE_EFFECTS] =
      convertTo<uint8_t>(availableEffects);
  return *this;
}

MetadataBuilder& MetadataBuilder::setControlAfAvailableModes(
    const std::vector<camera_metadata_enum_android_control_af_mode_t>&
        availableModes) {
  mEntryMap[ANDROID_CONTROL_AF_AVAILABLE_MODES] =
      convertTo<uint8_t>(availableModes);
  return *this;
}

MetadataBuilder& MetadataBuilder::setControlAfMode(
    const camera_metadata_enum_android_control_af_mode_t mode) {
  mEntryMap[ANDROID_CONTROL_AF_MODE] =
      std::vector<uint8_t>({static_cast<uint8_t>(mode)});
  return *this;
}

MetadataBuilder& MetadataBuilder::setControlAeAvailableFpsRange(
    const int32_t minFps, const int32_t maxFps) {
  mEntryMap[ANDROID_CONTROL_AE_AVAILABLE_TARGET_FPS_RANGES] =
      std::vector<int32_t>({minFps, maxFps});
  return *this;
}

MetadataBuilder& MetadataBuilder::setControlMaxRegions(int32_t maxAeRegions,
                                                       int32_t maxAwbRegions,
                                                       int32_t maxAfRegions) {
  mEntryMap[ANDROID_CONTROL_MAX_REGIONS] =
      std::vector<int32_t>({maxAeRegions, maxAwbRegions, maxAfRegions});
  return *this;
}

MetadataBuilder& MetadataBuilder::setControlAvailableAwbModes(
    const std::vector<camera_metadata_enum_android_control_awb_mode>& awbModes) {
  mEntryMap[ANDROID_CONTROL_AWB_AVAILABLE_MODES] = convertTo<uint8_t>(awbModes);
  return *this;
}

MetadataBuilder& MetadataBuilder::setControlAwbLockAvailable(
    const bool awbLockAvailable) {
  const uint8_t lockAvailable = awbLockAvailable
                                    ? ANDROID_CONTROL_AWB_LOCK_AVAILABLE_TRUE
                                    : ANDROID_CONTROL_AWB_LOCK_AVAILABLE_FALSE;
  mEntryMap[ANDROID_CONTROL_AWB_LOCK_AVAILABLE] =
      std::vector<uint8_t>({lockAvailable});
  return *this;
}

MetadataBuilder& MetadataBuilder::setControlAeLockAvailable(
    const bool aeLockAvailable) {
  const uint8_t lockAvailable = aeLockAvailable
                                    ? ANDROID_CONTROL_AE_LOCK_AVAILABLE_TRUE
                                    : ANDROID_CONTROL_AE_LOCK_AVAILABLE_FALSE;
  mEntryMap[ANDROID_CONTROL_AE_LOCK_AVAILABLE] =
      std::vector<uint8_t>({lockAvailable});
  return *this;
}

MetadataBuilder& MetadataBuilder::setControlAeRegions(
    const std::vector<ControlRegion>& aeRegions) {
  std::vector<int32_t> regions;
  regions.reserve(5 * aeRegions.size());
  for (const ControlRegion& region : aeRegions) {
    regions.push_back(region.x0);
    regions.push_back(region.y0);
    regions.push_back(region.x1);
    regions.push_back(region.y1);
    regions.push_back(region.weight);
  }
  mEntryMap[ANDROID_CONTROL_AE_REGIONS] = std::move(regions);
  return *this;
}

MetadataBuilder& MetadataBuilder::setControlAfRegions(
    const std::vector<ControlRegion>& afRegions) {
  std::vector<int32_t> regions;
  regions.reserve(5 * afRegions.size());
  for (const ControlRegion& region : afRegions) {
    regions.push_back(region.x0);
    regions.push_back(region.y0);
    regions.push_back(region.x1);
    regions.push_back(region.y1);
    regions.push_back(region.weight);
  }
  mEntryMap[ANDROID_CONTROL_AF_REGIONS] = std::move(regions);
  return *this;
}

MetadataBuilder& MetadataBuilder::setControlAwbRegions(
    const std::vector<ControlRegion>& awbRegions) {
  std::vector<int32_t> regions;
  regions.reserve(5 * awbRegions.size());
  for (const ControlRegion& region : awbRegions) {
    regions.push_back(region.x0);
    regions.push_back(region.y0);
    regions.push_back(region.x1);
    regions.push_back(region.y1);
    regions.push_back(region.weight);
  }
  mEntryMap[ANDROID_CONTROL_AWB_REGIONS] = std::move(regions);
  return *this;
}

MetadataBuilder& MetadataBuilder::setControlCaptureIntent(
    const camera_metadata_enum_android_control_capture_intent_t intent) {
  mEntryMap[ANDROID_CONTROL_CAPTURE_INTENT] =
      std::vector<uint8_t>({static_cast<uint8_t>(intent)});
  return *this;
}

MetadataBuilder& MetadataBuilder::setMaxJpegSize(const int32_t size) {
  mEntryMap[ANDROID_JPEG_MAX_SIZE] = std::vector<int32_t>({size});
  return *this;
}

MetadataBuilder& MetadataBuilder::setMaxNumberOutputStreams(
    const int32_t maxRawStreams, const int32_t maxProcessedStreams,
    const int32_t maxStallStreams) {
  mEntryMap[ANDROID_REQUEST_MAX_NUM_OUTPUT_STREAMS] = std::vector<int32_t>(
      {maxRawStreams, maxProcessedStreams, maxStallStreams});
  return *this;
}

MetadataBuilder& MetadataBuilder::setSyncMaxLatency(
    camera_metadata_enum_android_sync_max_latency latency) {
  mEntryMap[ANDROID_SYNC_MAX_LATENCY] =
      std::vector<int32_t>({static_cast<int32_t>(latency)});
  return *this;
}

MetadataBuilder& MetadataBuilder::setAvailableRequestCapabilities(
    const std::vector<camera_metadata_enum_android_request_available_capabilities_t>&
        requestCapabilities) {
  mEntryMap[ANDROID_REQUEST_AVAILABLE_CAPABILITIES] =
      convertTo<uint8_t>(requestCapabilities);
  return *this;
}

MetadataBuilder& MetadataBuilder::setAvailableOutputStreamConfigurations(
    const std::vector<StreamConfiguration>& streamConfigurations) {
  std::vector<int32_t> metadataStreamConfigs;
  std::vector<int64_t> metadataMinFrameDurations;
  std::vector<int64_t> metadataStallDurations;
  metadataStreamConfigs.reserve(streamConfigurations.size());
  metadataMinFrameDurations.reserve(streamConfigurations.size());
  metadataStallDurations.reserve(streamConfigurations.size());

  for (const auto& config : streamConfigurations) {
    metadataStreamConfigs.push_back(config.format);
    metadataStreamConfigs.push_back(config.width);
    metadataStreamConfigs.push_back(config.height);
    metadataStreamConfigs.push_back(
        ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS_OUTPUT);

    metadataMinFrameDurations.push_back(config.format);
    metadataMinFrameDurations.push_back(config.width);
    metadataMinFrameDurations.push_back(config.height);
    metadataMinFrameDurations.push_back(config.minFrameDuration.count());

    metadataStallDurations.push_back(config.format);
    metadataStallDurations.push_back(config.width);
    metadataStallDurations.push_back(config.height);
    metadataStallDurations.push_back(config.minStallDuration.count());
  }

  mEntryMap[ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS] =
      metadataStreamConfigs;
  mEntryMap[ANDROID_SCALER_AVAILABLE_MIN_FRAME_DURATIONS] =
      metadataMinFrameDurations;
  mEntryMap[ANDROID_SCALER_AVAILABLE_STALL_DURATIONS] = metadataStallDurations;

  return *this;
}

MetadataBuilder& MetadataBuilder::setAvailableMaxDigitalZoom(const float maxZoom) {
  mEntryMap[ANDROID_SCALER_AVAILABLE_MAX_DIGITAL_ZOOM] =
      std::vector<float>({maxZoom});
  return *this;
}

MetadataBuilder& MetadataBuilder::setControlZoomRatioRange(const float min,
                                                           const float max) {
  mEntryMap[ANDROID_CONTROL_ZOOM_RATIO_RANGE] = std::vector<float>({min, max});
  return *this;
}

MetadataBuilder& MetadataBuilder::setSensorActiveArraySize(int x0, int y0,
                                                           int x1, int y1) {
  mEntryMap[ANDROID_SENSOR_INFO_ACTIVE_ARRAY_SIZE] =
      std::vector<int32_t>({x0, y0, x1, y1});
  return *this;
}

MetadataBuilder& MetadataBuilder::setSensorPixelArraySize(int width,
                                                          int height) {
  mEntryMap[ANDROID_SENSOR_INFO_PIXEL_ARRAY_SIZE] =
      std::vector<int32_t>({width, height});
  return *this;
}

MetadataBuilder& MetadataBuilder::setSensorPhysicalSize(float width,
                                                        float height) {
  mEntryMap[ANDROID_SENSOR_INFO_PHYSICAL_SIZE] =
      std::vector<float>({width, height});
  return *this;
}

MetadataBuilder& MetadataBuilder::setControlAeCompensationRange(int32_t min,
                                                                int32_t max) {
  mEntryMap[ANDROID_CONTROL_AE_COMPENSATION_RANGE] =
      std::vector<int32_t>({min, max});
  return *this;
}

MetadataBuilder& MetadataBuilder::setControlAeCompensationStep(
    const camera_metadata_rational step) {
  mEntryMap[ANDROID_CONTROL_AE_COMPENSATION_STEP] =
      std::vector<camera_metadata_rational>({step});
  return *this;
}

MetadataBuilder& MetadataBuilder::setAvailableRequestKeys(
    const std::vector<int32_t>& keys) {
  mEntryMap[ANDROID_REQUEST_AVAILABLE_REQUEST_KEYS] = keys;
  return *this;
}

MetadataBuilder& MetadataBuilder::setAvailableResultKeys(
    const std::vector<int32_t>& keys) {
  mEntryMap[ANDROID_REQUEST_AVAILABLE_RESULT_KEYS] = keys;
  return *this;
}

MetadataBuilder& MetadataBuilder::setAvailableCapabilities(
    const std::vector<camera_metadata_enum_android_request_available_capabilities_t>&
        capabilities) {
  mEntryMap[ANDROID_REQUEST_AVAILABLE_CAPABILITIES] =
      convertTo<uint8_t>(capabilities);
  return *this;
}

MetadataBuilder& MetadataBuilder::setAvailableCharacteristicKeys(
    const std::vector<camera_metadata_tag_t>& keys) {
  mEntryMap[ANDROID_REQUEST_AVAILABLE_CHARACTERISTICS_KEYS] =
      convertTo<int32_t>(keys);
  return *this;
}

MetadataBuilder& MetadataBuilder::setAvailableCharacteristicKeys() {
  std::vector<camera_metadata_tag_t> availableKeys;
  availableKeys.reserve(mEntryMap.size());
  for (const auto& [key, _] : mEntryMap) {
    if (key != ANDROID_REQUEST_AVAILABLE_CHARACTERISTICS_KEYS) {
      availableKeys.push_back(key);
    }
  }
  setAvailableCharacteristicKeys(availableKeys);
  return *this;
}

std::unique_ptr<aidl::android::hardware::camera::device::CameraMetadata>
MetadataBuilder::build() const {
  CameraMetadata metadataHelper;
  for (const auto& entry : mEntryMap) {
    status_t ret = std::visit(
        [&](auto&& arg) {
          return metadataHelper.update(entry.first, arg.data(), arg.size());
        },
        entry.second);
    if (ret != NO_ERROR) {
      ALOGE("Failed to update metadata with key %d - %s: %s", entry.first,
            get_camera_metadata_tag_name(entry.first),
            ::android::statusToString(ret).c_str());
      return nullptr;
    }
  }

  const camera_metadata_t* metadata = metadataHelper.getAndLock();
  if (metadata == nullptr) {
    ALOGE(
        "Failure when constructing metadata -> CameraMetadata helper returned "
        "nullptr");
    return nullptr;
  }

  auto aidlMetadata =
      std::make_unique<aidl::android::hardware::camera::device::CameraMetadata>();
  const uint8_t* data_ptr = reinterpret_cast<const uint8_t*>(metadata);
  aidlMetadata->metadata.assign(data_ptr,
                                data_ptr + get_camera_metadata_size(metadata));
  metadataHelper.unlock(metadata);

  return aidlMetadata;
}

}  // namespace virtualcamera
}  // namespace companion
}  // namespace android
