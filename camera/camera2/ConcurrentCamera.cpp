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

#include <binder/Parcel.h>

namespace android {
namespace hardware {
namespace camera2 {
namespace utils {

ConcurrentCameraIdCombination::ConcurrentCameraIdCombination() = default;

ConcurrentCameraIdCombination::ConcurrentCameraIdCombination(
        std::vector<std::string> &&combination) : mConcurrentCameraIds(std::move(combination)) { }

ConcurrentCameraIdCombination::~ConcurrentCameraIdCombination() = default;

status_t ConcurrentCameraIdCombination::readFromParcel(const android::Parcel* parcel) {
    if (parcel == nullptr) {
        ALOGE("%s: Null parcel", __FUNCTION__);
        return BAD_VALUE;
    }
    status_t err = OK;
    mConcurrentCameraIds.clear();
    int32_t cameraIdCount = 0;
    if ((err = parcel->readInt32(&cameraIdCount)) != OK) {
        ALOGE("%s: Failed to read the camera id count from parcel: %d", __FUNCTION__, err);
        return err;
    }
    for (int32_t i = 0; i < cameraIdCount; i++) {
        String16 id;
        if ((err = parcel->readString16(&id)) != OK) {
            ALOGE("%s: Failed to read camera id!", __FUNCTION__);
            return err;
        }
        mConcurrentCameraIds.push_back(std::string(String8(id).string()));
    }
    return OK;
}

status_t ConcurrentCameraIdCombination::writeToParcel(android::Parcel* parcel) const {

    if (parcel == nullptr) {
        ALOGE("%s: Null parcel", __FUNCTION__);
        return BAD_VALUE;
    }

    status_t err = OK;

    if ((err = parcel->writeInt32(mConcurrentCameraIds.size())) != OK) {
        ALOGE("%s: Failed to write the camera id count to parcel: %d", __FUNCTION__, err);
        return err;
    }

    for (const auto &it : mConcurrentCameraIds) {
        if ((err = parcel->writeString16(String16(it.c_str()))) != OK) {
            ALOGE("%s: Failed to write the camera id string to parcel: %d", __FUNCTION__, err);
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
    mCameraId = std::string(String8(id).string());
    return OK;
}

status_t CameraIdAndSessionConfiguration::writeToParcel(android::Parcel* parcel) const {

    if (parcel == nullptr) {
        ALOGE("%s: Null parcel", __FUNCTION__);
        return BAD_VALUE;
    }

    status_t err = OK;
    if ((err = parcel->writeString16(String16(mCameraId.c_str()))) != OK) {
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
