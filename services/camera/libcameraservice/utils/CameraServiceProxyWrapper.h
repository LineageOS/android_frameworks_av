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

#ifndef ANDROID_SERVERS_CAMERA_SERVICE_PROXY_WRAPPER_H_
#define ANDROID_SERVERS_CAMERA_SERVICE_PROXY_WRAPPER_H_

#include <android/hardware/ICameraServiceProxy.h>

#include <utils/Mutex.h>
#include <utils/String8.h>
#include <utils/String16.h>
#include <utils/StrongPointer.h>
#include <utils/Timers.h>

#include <camera/CameraSessionStats.h>

namespace android {

class CameraServiceProxyWrapper {
private:
    // Guard mCameraServiceProxy
    Mutex mProxyMutex;
    // Cached interface to the camera service proxy in system service
    sp<hardware::ICameraServiceProxy> mCameraServiceProxy;

    class CameraSessionStatsWrapper {
    private:
        hardware::CameraSessionStats mSessionStats;
        Mutex mLock; // lock for per camera session stats

        /**
         * Update the session stats of a given camera device (open/close/active/idle) with
         * the camera proxy service in the system service
         */
        void updateProxyDeviceState(sp<hardware::ICameraServiceProxy>& proxyBinder);

    public:
        CameraSessionStatsWrapper(const String16& cameraId, int facing, int newCameraState,
                const String16& clientName, int apiLevel, bool isNdk, int32_t latencyMs) :
            mSessionStats(cameraId, facing, newCameraState, clientName, apiLevel, isNdk, latencyMs)
            { }

        void onOpen(sp<hardware::ICameraServiceProxy>& proxyBinder);
        void onClose(sp<hardware::ICameraServiceProxy>& proxyBinder, int32_t latencyMs);
        void onStreamConfigured(int operatingMode, bool internalReconfig, int32_t latencyMs);
        void onActive(sp<hardware::ICameraServiceProxy>& proxyBinder, float maxPreviewFps);
        void onIdle(sp<hardware::ICameraServiceProxy>& proxyBinder,
                int64_t requestCount, int64_t resultErrorCount, bool deviceError,
                const std::string& userTag, int32_t videoStabilizationMode,
                const std::vector<hardware::CameraStreamStats>& streamStats);
    };

    // Lock for camera session stats map
    Mutex mLock;
    // Map from camera id to the camera's session statistics
    std::map<String8, std::shared_ptr<CameraSessionStatsWrapper>> mSessionStatsMap;

    sp<hardware::ICameraServiceProxy> getCameraServiceProxy();

public:
    CameraServiceProxyWrapper(sp<hardware::ICameraServiceProxy> serviceProxy = nullptr) :
            mCameraServiceProxy(serviceProxy)
    { }

    static sp<hardware::ICameraServiceProxy> getDefaultCameraServiceProxy();

    // Open
    void logOpen(const String8& id, int facing,
            const String16& clientPackageName, int apiLevel, bool isNdk,
            int32_t latencyMs);

    // Close
    void logClose(const String8& id, int32_t latencyMs);

    // Stream configuration
    void logStreamConfigured(const String8& id, int operatingMode, bool internalReconfig,
            int32_t latencyMs);

    // Session state becomes active
    void logActive(const String8& id, float maxPreviewFps);

    // Session state becomes idle
    void logIdle(const String8& id,
            int64_t requestCount, int64_t resultErrorCount, bool deviceError,
            const std::string& userTag, int32_t videoStabilizationMode,
            const std::vector<hardware::CameraStreamStats>& streamStats);

    // Ping camera service proxy for user update
    void pingCameraServiceProxy();

    // Return the current top activity rotate and crop override.
    int getRotateAndCropOverride(String16 packageName, int lensFacing, int userId);

    // Return the current top activity autoframing.
    int getAutoframingOverride(const String16& packageName);

    // Detect if the camera is disabled by device policy.
    bool isCameraDisabled(int userId);
};

} // android

#endif // ANDROID_SERVERS_CAMERA_SERVICE_PROXY_WRAPPER_H_
