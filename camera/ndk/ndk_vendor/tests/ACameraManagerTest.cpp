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

#define LOG_TAG "ACameraManagerTest"
//#define LOG_NDEBUG 0

#include <gtest/gtest.h>

#include <mutex>
#include <set>
#include <string>

#include <utils/Log.h>
#include <camera/NdkCameraError.h>
#include <camera/NdkCameraManager.h>

namespace {

class CameraServiceListener {
  public:
    typedef std::set<std::pair<std::string, std::string>> StringPairSet;

    static void onAvailable(void* obj, const char* cameraId) {
        ALOGV("Camera %s onAvailable", cameraId);
        if (obj == nullptr) {
            return;
        }
        CameraServiceListener* thiz = reinterpret_cast<CameraServiceListener*>(obj);
        std::lock_guard<std::mutex> lock(thiz->mMutex);
        thiz->mOnAvailableCount++;
        thiz->mAvailableMap[cameraId] = true;
        return;
    }

    static void onUnavailable(void* obj, const char* cameraId) {
        ALOGV("Camera %s onUnavailable", cameraId);
        if (obj == nullptr) {
            return;
        }
        CameraServiceListener* thiz = reinterpret_cast<CameraServiceListener*>(obj);
        std::lock_guard<std::mutex> lock(thiz->mMutex);
        thiz->mOnUnavailableCount++;
        thiz->mAvailableMap[cameraId] = false;
        return;
    }

    static void onCameraAccessPrioritiesChanged(void* /*obj*/) {
        return;
    }

    static void onPhysicalCameraAvailable(void* obj, const char* cameraId,
            const char* physicalCameraId) {
        ALOGV("Camera %s : %s onAvailable", cameraId, physicalCameraId);
        if (obj == nullptr) {
            return;
        }
        CameraServiceListener* thiz = reinterpret_cast<CameraServiceListener*>(obj);
        std::lock_guard<std::mutex> lock(thiz->mMutex);
        thiz->mOnPhysicalCameraAvailableCount++;
        return;
    }

    static void onPhysicalCameraUnavailable(void* obj, const char* cameraId,
            const char* physicalCameraId) {
        ALOGV("Camera %s : %s onUnavailable", cameraId, physicalCameraId);
        if (obj == nullptr) {
            return;
        }
        CameraServiceListener* thiz = reinterpret_cast<CameraServiceListener*>(obj);
        std::lock_guard<std::mutex> lock(thiz->mMutex);
        thiz->mUnavailablePhysicalCameras.emplace(cameraId, physicalCameraId);
        return;
    }

    void resetCount() {
        std::lock_guard<std::mutex> lock(mMutex);
        mOnAvailableCount = 0;
        mOnUnavailableCount = 0;
        mOnPhysicalCameraAvailableCount = 0;
        mUnavailablePhysicalCameras.clear();
        return;
    }

    int getAvailableCount() {
        std::lock_guard<std::mutex> lock(mMutex);
        return mOnAvailableCount;
    }

    int getUnavailableCount() {
        std::lock_guard<std::mutex> lock(mMutex);
        return mOnUnavailableCount;
    }

    int getPhysicalCameraAvailableCount() {
        std::lock_guard<std::mutex> lock(mMutex);
        return mOnPhysicalCameraAvailableCount;
    }

    StringPairSet getUnavailablePhysicalCameras() {
        std::lock_guard<std::mutex> lock(mMutex);
        return mUnavailablePhysicalCameras;
    }

    bool isAvailable(const char* cameraId) {
        std::lock_guard<std::mutex> lock(mMutex);
        if (mAvailableMap.count(cameraId) == 0) {
            return false;
        }
        return mAvailableMap[cameraId];
    }

  private:
    std::mutex mMutex;
    int mOnAvailableCount = 0;
    int mOnUnavailableCount = 0;
    int mOnPhysicalCameraAvailableCount = 0;
    std::map<std::string, bool> mAvailableMap;
    StringPairSet mUnavailablePhysicalCameras;
};

class ACameraManagerTest : public ::testing::Test {
  public:
    void SetUp() override {
        mCameraManager = ACameraManager_create();
        if (mCameraManager == nullptr) {
            ALOGE("Failed to create ACameraManager.");
            return;
        }

        camera_status_t ret = ACameraManager_getCameraIdList(mCameraManager, &mCameraIdList);
        if (ret != ACAMERA_OK) {
            ALOGE("Failed to get cameraIdList: ret=%d", ret);
            return;
        }
        if (mCameraIdList->numCameras < 1) {
            ALOGW("Device has no camera on board.");
            return;
        }
    }
    void TearDown() override {
        // Destroy camera manager
        if (mCameraIdList) {
            ACameraManager_deleteCameraIdList(mCameraIdList);
            mCameraIdList = nullptr;
        }
        if (mCameraManager) {
            ACameraManager_delete(mCameraManager);
            mCameraManager = nullptr;
        }
    }

    // Camera manager
    ACameraManager* mCameraManager = nullptr;
    ACameraIdList* mCameraIdList = nullptr;
    CameraServiceListener mAvailabilityListener;
    ACameraManager_ExtendedAvailabilityCallbacks mCbs = {
        {
            &mAvailabilityListener,
                CameraServiceListener::onAvailable,
                CameraServiceListener::onUnavailable
        },
        CameraServiceListener::onCameraAccessPrioritiesChanged,
        CameraServiceListener::onPhysicalCameraAvailable,
        CameraServiceListener::onPhysicalCameraUnavailable,
        {}
    };
};

TEST_F(ACameraManagerTest, testCameraManagerExtendedAvailabilityCallbacks) {
    camera_status_t ret = ACameraManager_registerExtendedAvailabilityCallback(mCameraManager,
            &mCbs);
    ASSERT_EQ(ret, ACAMERA_OK);

    sleep(1);

    // Should at least get onAvailable for each camera once
    ASSERT_EQ(mAvailabilityListener.getAvailableCount(), mCameraIdList->numCameras);

    // Expect no available callbacks for physical cameras
    int availablePhysicalCamera = mAvailabilityListener.getPhysicalCameraAvailableCount();
    ASSERT_EQ(availablePhysicalCamera, 0);

    CameraServiceListener::StringPairSet unavailablePhysicalCameras;
    CameraServiceListener::StringPairSet physicalCameraIdPairs;

    unavailablePhysicalCameras = mAvailabilityListener.getUnavailablePhysicalCameras();
    for (int i = 0; i < mCameraIdList->numCameras; i++) {
        const char* cameraId = mCameraIdList->cameraIds[i];
        ASSERT_NE(cameraId, nullptr);
        ASSERT_TRUE(mAvailabilityListener.isAvailable(cameraId));

        ACameraMetadata* chars = nullptr;
        ret = ACameraManager_getCameraCharacteristics(mCameraManager, cameraId, &chars);
        ASSERT_EQ(ret, ACAMERA_OK);
        ASSERT_NE(chars, nullptr);

        size_t physicalCameraCnt = 0;
        const char *const* physicalCameraIds = nullptr;
        if (!ACameraMetadata_isLogicalMultiCamera(
                chars, &physicalCameraCnt, &physicalCameraIds)) {
            ACameraMetadata_free(chars);
            continue;
        }
        for (size_t j = 0; j < physicalCameraCnt; j++) {
            physicalCameraIdPairs.emplace(cameraId, physicalCameraIds[j]);
        }
        ACameraMetadata_free(chars);
    }
    for (const auto& unavailIdPair : unavailablePhysicalCameras) {
        bool validPair = false;
        for (const auto& idPair : physicalCameraIdPairs) {
            if (idPair.first == unavailIdPair.first && idPair.second == unavailIdPair.second) {
                validPair = true;
                break;
            }
        }
        // Expect valid unavailable physical cameras
        ASSERT_TRUE(validPair);
    }

    ret = ACameraManager_unregisterExtendedAvailabilityCallback(mCameraManager, &mCbs);
    ASSERT_EQ(ret, ACAMERA_OK);
}

}  // namespace
