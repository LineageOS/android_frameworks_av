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

//#define LOG_NDEBUG 0
#define LOG_TAG "VirtualDeviceCameraIdMapper"

#include <android_companion_virtualdevice_flags.h>
#include <camera/CameraUtils.h>

#include "VirtualDeviceCameraIdMapper.h"

namespace android {

namespace vd_flags = android::companion::virtualdevice::flags;

void VirtualDeviceCameraIdMapper::addCamera(const std::string& cameraId,
        int32_t deviceId, const std::string& mappedCameraId) {
    if (!vd_flags::camera_device_awareness()) {
        ALOGD("%s: Device-aware camera feature is not enabled", __func__);
        return;
    }

    if (deviceId == kDefaultDeviceId) {
        ALOGD("%s: Not adding entry for a camera of the default device", __func__);
        return;
    }

    ALOGD("%s: Adding camera %s for device %d with mapped id %s", __func__, cameraId.c_str(),
          deviceId, mappedCameraId.c_str());

    std::scoped_lock lock(mLock);
    mDeviceIdMappedCameraIdPairToCameraIdMap[{deviceId, mappedCameraId}] = cameraId;
}

void VirtualDeviceCameraIdMapper::removeCamera(const std::string& cameraId) {
    if (!vd_flags::camera_device_awareness()) {
        ALOGD("%s: Device-aware camera feature is not enabled", __func__);
        return;
    }

    std::scoped_lock lock(mLock);
    for (auto it = mDeviceIdMappedCameraIdPairToCameraIdMap.begin();
         it != mDeviceIdMappedCameraIdPairToCameraIdMap.end(); ++it) {
        if (it->first.second == cameraId) {
            mDeviceIdMappedCameraIdPairToCameraIdMap.erase(it);
            return;
        }
    }
}

std::optional<std::string> VirtualDeviceCameraIdMapper::getActualCameraId(
        int32_t deviceId, const std::string& mappedCameraId) const {
    if (deviceId == kDefaultDeviceId) {
        ALOGD("%s: Returning the camera id as the mapped camera id for camera %s, as it "
              "belongs to the default device", __func__, mappedCameraId.c_str());
        return mappedCameraId;
    }

    if (!vd_flags::camera_device_awareness()) {
        ALOGD("%s: Device-aware camera feature is not enabled, returning the camera id as "
              "the mapped camera id for camera %s", __func__, mappedCameraId.c_str());
        return mappedCameraId;
    }

    std::scoped_lock lock(mLock);
    auto iterator = mDeviceIdMappedCameraIdPairToCameraIdMap.find(
            {deviceId, mappedCameraId});
    if (iterator == mDeviceIdMappedCameraIdPairToCameraIdMap.end()) {
        ALOGW("%s: No entry found for device id %d and mapped camera id %s", __func__,
              deviceId, mappedCameraId.c_str());
        return std::nullopt;
    }
    return iterator->second;
}

std::pair<int32_t, std::string> VirtualDeviceCameraIdMapper::getDeviceIdAndMappedCameraIdPair(
        const std::string& cameraId) const {
    if (!vd_flags::camera_device_awareness()) {
        ALOGD("%s: Device-aware camera feature is not enabled", __func__);
        return std::make_pair(kDefaultDeviceId, cameraId);
    }

    std::scoped_lock lock(mLock);
    for (const auto& [deviceIdMappedCameraIdPair, actualCameraId]
            : mDeviceIdMappedCameraIdPairToCameraIdMap) {
        if (actualCameraId == cameraId) {
            return deviceIdMappedCameraIdPair;
        }
    }
    ALOGV("%s: No device id and mapped camera id found for camera id %s, so it must belong "
            "to the default device ? ", __func__, cameraId.c_str());
    return std::make_pair(kDefaultDeviceId, cameraId);
}

int VirtualDeviceCameraIdMapper::getNumberOfCameras(int32_t deviceId) const {
    if (!vd_flags::camera_device_awareness()) {
        return 0;
    }

    int numOfCameras = 0;
    std::scoped_lock lock(mLock);
    for (const auto& [deviceIdMappedCameraIdPair, _]
            : mDeviceIdMappedCameraIdPairToCameraIdMap) {
        if (deviceIdMappedCameraIdPair.first == deviceId) {
            numOfCameras++;
        }
    }
    return numOfCameras;
}

std::optional<std::string> VirtualDeviceCameraIdMapper::getActualCameraId(
        int api1CameraId, int32_t deviceId) const {
    if (!vd_flags::camera_device_awareness()) {
        ALOGD("%s: Device-aware camera feature is not enabled", __func__);
        return std::nullopt;
    }

    int matchingCameraIndex = 0;
    std::scoped_lock lock(mLock);
    for (const auto& [deviceIdMappedCameraIdPair, actualCameraId]
            : mDeviceIdMappedCameraIdPairToCameraIdMap) {
        if (deviceIdMappedCameraIdPair.first == deviceId) {
            if (matchingCameraIndex == api1CameraId) {
                return actualCameraId;
            }
            matchingCameraIndex++;
        }
    }
    ALOGW("%s: No entry found for device id %d and API 1 camera id %d", __func__,
          deviceId, api1CameraId);
    return std::nullopt;
}

} // namespace android