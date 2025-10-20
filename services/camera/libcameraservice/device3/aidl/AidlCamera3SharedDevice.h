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

#ifndef ANDROID_SERVERS_AIDLCAMERA3SHAREDDEVICE_H
#define ANDROID_SERVERS_AIDLCAMERA3SHAREDDEVICE_H

#include <camera/camera2/OutputConfiguration.h>
#include "common/FrameProcessorBase.h"
#include "../Camera3SharedOutputStream.h"
#include "AidlCamera3Device.h"
namespace android {

/**
 * Shared CameraDevice for AIDL HAL devices.
 */
using ::android::camera3::Camera3SharedOutputStream;
class AidlCamera3SharedDevice :
        public AidlCamera3Device,
        public NotificationListener {
  public:
    static sp<AidlCamera3SharedDevice> getInstance(
            std::shared_ptr<CameraServiceProxyWrapper>& cameraServiceProxyWrapper,
            std::shared_ptr<AttributionAndPermissionUtils> attributionAndPermissionUtils,
            const std::string& id, bool overrideForPerfClass,
            const CameraCompatibilityInfo& compatInfo,
            bool isVendorClient, bool legacyClient = false);
    status_t initialize(sp<CameraProviderManager> manager,
            const std::string& monitorTags) override;
    status_t disconnectClient(int clientPid) override;
    status_t beginConfigure() override;
    status_t getSharedStreamIds(const OutputStreamInfo &config,
            std::vector<int>& streamIds) override;
    status_t addSharedSurfaces(int streamId,
            const std::vector<android::camera3::OutputStreamInfo> &outputInfo,
            const std::vector<SurfaceHolder>& surfaces,
            std::vector<int> *surfaceIds = nullptr) override;
    status_t removeSharedSurfaces(int streamId,
            const std::vector<size_t> &surfaceIds) override;
    status_t setSharedStreamingRequest(const PhysicalCameraSettingsList &request,
            const SurfaceMap &surfaceMap, int32_t *sharedReqID, int64_t *lastFrameNumber = NULL)
            override;
    status_t clearSharedStreamingRequest(int64_t *lastFrameNumber = NULL) override;
    status_t setSharedCaptureRequest(const PhysicalCameraSettingsList &request,
            const SurfaceMap &surfaceMap, int32_t *sharedReqID, int64_t *lastFrameNumber = NULL)
            override;
    sp<camera2::FrameProcessorBase> getSharedFrameProcessor() override {return mFrameProcessor;};
    status_t startStreaming(const int32_t reqId, const SurfaceMap &surfaceMap,
            int32_t *sharedReqID, int64_t *lastFrameNumber = NULL);

    status_t setNotifyCallback(wp<NotificationListener> listener) override;
    virtual void notifyError(int32_t errorCode,
                             const CaptureResultExtras &resultExtras) override;
    virtual status_t notifyActive(float maxPreviewFps) override;
    virtual void notifyIdle(int64_t requestCount, int64_t resultError, bool deviceError,
            std::pair<int32_t, int32_t> mostRequestedFpsRange,
            const std::vector<hardware::CameraStreamStats>& streamStats) override;
    virtual void notifyShutter(const CaptureResultExtras &resultExtras,
            nsecs_t timestamp) override;
    virtual void notifyRequestQueueEmpty() {};
    // Prepare api not supported for shared session
    virtual void notifyPrepared(int /*streamId*/) {};
    // Required only for API1
    virtual void notifyAutoFocus(uint8_t /*newState*/, int /*triggerId*/) {};
    virtual void notifyAutoExposure(uint8_t /*newState*/, int /*triggerId*/) {};
    virtual void notifyAutoWhitebalance(uint8_t /*newState*/,
            int /*triggerId*/) {};
    virtual void notifyRepeatingRequestError(long /*lastFrameNumber*/) {};
  private:
    static std::map<std::string, sp<AidlCamera3SharedDevice>> sSharedDevices;
    static std::map<std::string, std::unordered_set<int>> sClientsPid;
    static Mutex sSharedClientsLock;
    AidlCamera3SharedDevice(
            std::shared_ptr<CameraServiceProxyWrapper>& cameraServiceProxyWrapper,
            std::shared_ptr<AttributionAndPermissionUtils> attributionAndPermissionUtils,
            const std::string& id, bool overrideForPerfClass,
            const CameraCompatibilityInfo& compatInfo,
            bool isVendorClient, bool legacyClient)
        : AidlCamera3Device(cameraServiceProxyWrapper, attributionAndPermissionUtils, id,
                  overrideForPerfClass, compatInfo, isVendorClient, legacyClient),
        mStreamingRequestId(REQUEST_ID_NONE),
        mRequestIdCounter(0) {}
    std::vector<OutputConfiguration> getSharedOutputConfiguration();
    std::vector<OutputConfiguration> mSharedOutputConfigurations;
    std::vector<int> mSharedSurfaceIds;
    std::vector<sp<Surface>> mSharedSurfaces;
    std::vector<sp<BufferItemConsumer>> mOpaqueConsumers;
    std::unordered_map<int32_t, OutputStreamInfo> mStreamInfoMap;
    // Streaming request ID
    int32_t mStreamingRequestId;
    static const int32_t REQUEST_ID_NONE = -1;
    int32_t mRequestIdCounter;
    std::unordered_map<int, int32_t> mClientRequestIds;
    std::unordered_map<int, SurfaceMap> mClientSurfaces;
    std::unordered_map<int, wp<NotificationListener>> mClientListeners;
    SurfaceMap mergeSurfaceMaps(const SurfaceMap& map1, const SurfaceMap& map2);
    SurfaceMap removeClientSurfaceMap(const SurfaceMap& map1, const SurfaceMap& map2);
    Mutex mSharedDeviceLock;
    sp<camera2::FrameProcessorBase> mFrameProcessor;
}; // class AidlCamera3SharedDevice
}; // namespace android
#endif
