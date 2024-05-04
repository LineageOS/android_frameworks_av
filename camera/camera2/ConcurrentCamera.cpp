/*
 * Copyright (C) 2020 The Android Open Source Project
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
#define LOG_TAG "ConcurrentCamera"
#include <utils/Log.h>
#include <utils/String16.h>

#include <camera/camera2/ConcurrentCamera.h>
#include <camera/StringUtils.h>

#include <binder/Parcel.h>

namespace android {
namespace hardware {
namespace camera2 {
namespace utils {

ConcurrentCameraIdCombination::ConcurrentCameraIdCombination() = default;

ConcurrentCameraIdCombination::ConcurrentCameraIdCombination(
        std::vector<std::pair<std::string, int32_t>> &&combination)
            : mConcurrentCameraIdDeviceIdPairs(std::move(combination)) { }

ConcurrentCameraIdCombination::~ConcurrentCameraIdCombination() = default;

status_t ConcurrentCameraIdCombination::readFromParcel(const android::Parcel* parcel) {
    if (parcel == nullptr) {
        ALOGE("%s: Null parcel", __FUNCTION__);
        return BAD_VALUE;
    }
    status_t err = OK;
    mConcurrentCameraIdDeviceIdPairs.clear();
    int32_t cameraCount = 0;
    if ((err = parcel->readInt32(&cameraCount)) != OK) {
        ALOGE("%s: Failed to read the camera count from parcel: %d", __FUNCTION__, err);
        return err;
    }
    for (int32_t i = 0; i < cameraCount; i++) {
        String16 cameraId;
        if ((err = parcel->readString16(&cameraId)) != OK) {
            ALOGE("%s: Failed to read camera id!", __FUNCTION__);
            return err;
        }
        int32_t deviceId;
        if ((err = parcel->readInt32(&deviceId)) != OK) {
            ALOGE("%s: Failed to read device id!", __FUNCTION__);
            return err;
        }
        mConcurrentCameraIdDeviceIdPairs.push_back({toStdString(cameraId), deviceId});
    }
    return OK;
}

status_t ConcurrentCameraIdCombination::writeToParcel(android::Parcel* parcel) const {
    if (parcel == nullptr) {
        ALOGE("%s: Null parcel", __FUNCTION__);
        return BAD_VALUE;
    }

    status_t err = OK;

    if ((err = parcel->writeInt32(mConcurrentCameraIdDeviceIdPairs.size())) != OK) {
        ALOGE("%s: Failed to write the camera id count to parcel: %d", __FUNCTION__, err);
        return err;
    }

    for (const auto &it : mConcurrentCameraIdDeviceIdPairs) {
        if ((err = parcel->writeString16(toString16(it.first))) != OK) {
            ALOGE("%s: Failed to write the camera id string to parcel: %d", __FUNCTION__, err);
            return err;
        }
        if ((err = parcel->writeInt32(it.second)) != OK) {
            ALOGE("%s: Failed to write the device id integer to parcel: %d", __FUNCTION__, err);
            return err;
        }
    }
    return OK;
}

CameraIdAndSessionConfiguration::CameraIdAndSessionConfiguration() = default;
CameraIdAndSessionConfiguration::~CameraIdAndSessionConfiguration() = default;

status_t CameraIdAndSessionConfiguration::readFromParcel(const android::Parcel* parcel) {
    if (parcel == nullptr) {
        ALOGE("%s: Null parcel", __FUNCTION__);
        return BAD_VALUE;
    }
    status_t err = OK;
    String16 id;
    if ((err = parcel->readString16(&id)) != OK) {
        ALOGE("%s: Failed to read camera id!", __FUNCTION__);
        return err;
    }
    if ((err = mSessionConfiguration.readFromParcel(parcel)) != OK) {
        ALOGE("%s: Failed to read sessionConfiguration!", __FUNCTION__);
        return err;
    }
    mCameraId = toStdString(id);
    return OK;
}

status_t CameraIdAndSessionConfiguration::writeToParcel(android::Parcel* parcel) const {
    if (parcel == nullptr) {
        ALOGE("%s: Null parcel", __FUNCTION__);
        return BAD_VALUE;
    }

    status_t err = OK;
    if ((err = parcel->writeString16(toString16(mCameraId))) != OK) {
        ALOGE("%s: Failed to write camera id!", __FUNCTION__);
        return err;
    }

    if ((err = mSessionConfiguration.writeToParcel(parcel) != OK)) {
        ALOGE("%s: Failed to write session configuration!", __FUNCTION__);
        return err;
    }
    return OK;
}

} // namespace utils
} // namespace camera2
} // namespace hardware
} // namespace android
