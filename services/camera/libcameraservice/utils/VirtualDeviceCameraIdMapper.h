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

#ifndef ANDROID_SERVERS_CAMERA_VIRTUAL_DEVICE_CAMERA_ID_MAPPER_H
#define ANDROID_SERVERS_CAMERA_VIRTUAL_DEVICE_CAMERA_ID_MAPPER_H

#include <string>
#include <map>
#include <mutex>

#include <utils/Mutex.h>

namespace android {

class VirtualDeviceCameraIdMapper {
public:
    VirtualDeviceCameraIdMapper() {}

    virtual ~VirtualDeviceCameraIdMapper() {}

    void addCamera(const std::string& cameraId, int32_t deviceId,
            const std::string& mappedCameraId) EXCLUDES(mLock);

    void removeCamera(const std::string& cameraId) EXCLUDES(mLock);

    /**
     * Return the actual camera id for a given device id (i.e., the id of the device owning
     * the camera, for a virtual camera this would be the id of the virtual device, and for
     * any other cameras this would be default device id, i.e., 0) and mapped camera
     * id (for virtual devices, the back and front virtual cameras of that device would have
     * 0 and 1 respectively as their mapped camera id, and for any other cameras this
     * would be their actual camera id). When the camera device awareness flag is disabled,
     * this will return the given camera id itself.
     */
    std::optional<std::string> getActualCameraId(int32_t deviceId,
            const std::string& mappedCameraId) const EXCLUDES(mLock);

    /**
     * Return the device id (i.e., the id of the device owning the camera, for a virtual
     * camera this would be the id of the virtual device, and for any other cameras this
     * would be default device id, i.e., 0) and the mapped camera id (for virtual
     * devices, the back and front virtual cameras of that device would have 0 and 1
     * respectively as their mapped camera id, and for any other cameras this would
     * be their actual camera id) for a given camera id. When the camera device awareness flag is
     * disabled, this will return a pair of kDefaultDeviceId and the given cameraId.
     */
    std::pair<int32_t, std::string> getDeviceIdAndMappedCameraIdPair(
            const std::string& cameraId) const EXCLUDES(mLock);

    /**
     * Return the number of virtual cameras corresponding to the legacy camera API
     * getNumberOfCameras. When the camera device awareness flag is disabled, this will return 0.
     */
    int getNumberOfCameras(int32_t deviceId) const EXCLUDES(mLock);

    /**
     * Return the actual camera id corresponding to the virtual camera with the given API 1 camera
     * id. When the camera device awareness flag is disabled, this will return std::nullopt.
     */
    std::optional<std::string> getActualCameraId(int api1CameraId, int32_t deviceId)
            const EXCLUDES(mLock);

private:
    mutable std::mutex mLock;

    // Map of (deviceId, app-visible cameraId) -> HAL-visible cameraId
    std::map<std::pair<int32_t, std::string>, std::string>
            mDeviceIdMappedCameraIdPairToCameraIdMap GUARDED_BY(mLock);
};

} // namespace android

#endif // ANDROID_SERVERS_CAMERA_VIRTUAL_DEVICE_CAMERA_ID_MAPPER_H
