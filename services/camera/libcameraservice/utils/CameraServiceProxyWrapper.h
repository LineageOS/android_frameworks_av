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
#include <utils/StrongPointer.h>
#include <utils/Timers.h>
#include <random>
#include <string>

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
        CameraSessionStatsWrapper(const std::string& cameraId, int facing, int newCameraState,
                                  const std::string& clientName, int apiLevel, bool isNdk,
                                  int32_t latencyMs, int64_t logId)
            : mSessionStats(cameraId, facing, newCameraState, clientName, apiLevel, isNdk,
                            latencyMs, logId) {}

        void onOpen(sp<hardware::ICameraServiceProxy>& proxyBinder);
        void onClose(sp<hardware::ICameraServiceProxy>& proxyBinder, int32_t latencyMs,
                bool deviceError);
        void onStreamConfigured(int operatingMode, bool internalReconfig, int32_t latencyMs);
        void onActive(sp<hardware::ICameraServiceProxy>& proxyBinder, float maxPreviewFps);
        void onIdle(sp<hardware::ICameraServiceProxy>& proxyBinder,
                int64_t requestCount, int64_t resultErrorCount, bool deviceError,
                const std::string& userTag, int32_t videoStabilizationMode, bool usedUltraWide,
                bool usedZoomOverride, std::pair<int32_t, int32_t> mostRequestedFpsRange,
                const std::vector<hardware::CameraStreamStats>& streamStats);

        std::string updateExtensionSessionStats(
                const hardware::CameraExtensionSessionStats& extStats);

        // Returns the logId associated with this event.
        int64_t getLogId();
    };

    // Lock for camera session stats map
    Mutex mLock;
    // Map from camera id to the camera's session statistics
    std::map<std::string, std::shared_ptr<CameraSessionStatsWrapper>> mSessionStatsMap;

    std::random_device mRandomDevice;  // pulls 32-bit random numbers from /dev/urandom

    sp<hardware::ICameraServiceProxy> getCameraServiceProxy();

    // Returns a randomly generated ID that is suitable for logging the event. A new identifier
    // should only be generated for an open event. All other events for the cameraId should use the
    // ID generated for the open event associated with them.
    static int64_t generateLogId(std::random_device& randomDevice);

public:
    CameraServiceProxyWrapper(sp<hardware::ICameraServiceProxy> serviceProxy = nullptr) :
            mCameraServiceProxy(serviceProxy)
    { }

    static sp<hardware::ICameraServiceProxy> getDefaultCameraServiceProxy();

    // Open
    void logOpen(const std::string& id, int facing,
            const std::string& clientPackageName, int apiLevel, bool isNdk,
            int32_t latencyMs);

    // Close
    void logClose(const std::string& id, int32_t latencyMs, bool deviceError);

    // Stream configuration
    void logStreamConfigured(const std::string& id, int operatingMode, bool internalReconfig,
            int32_t latencyMs);

    // Session state becomes active
    void logActive(const std::string& id, float maxPreviewFps);

    // Session state becomes idle
    void logIdle(const std::string& id,
            int64_t requestCount, int64_t resultErrorCount, bool deviceError,
            const std::string& userTag, int32_t videoStabilizationMode, bool usedUltraWide,
            bool usedZoomOverride, std::pair<int32_t, int32_t> mostRequestedFpsRange,
            const std::vector<hardware::CameraStreamStats>& streamStats);

    // Ping camera service proxy for user update
    void pingCameraServiceProxy();

    // Return the current top activity rotate and crop override.
    int getRotateAndCropOverride(const std::string &packageName, int lensFacing, int userId);

    // Return the current top activity autoframing.
    int getAutoframingOverride(const std::string& packageName);

    // Detect if the camera is disabled by device policy.
    bool isCameraDisabled(int userId);

    // Returns the logId currently associated with the given cameraId. See 'mLogId' in
    // frameworks/av/camera/include/camera/CameraSessionStats.h for more details about this
    // identifier. Returns a non-0 value on success.
    int64_t getCurrentLogIdForCamera(const std::string& cameraId);

    // Update the stored extension stats to the latest values
    std::string updateExtensionStats(const hardware::CameraExtensionSessionStats& extStats);
};

} // android

#endif // ANDROID_SERVERS_CAMERA_SERVICE_PROXY_WRAPPER_H_
