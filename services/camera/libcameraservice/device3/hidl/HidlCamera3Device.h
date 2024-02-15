/*
 * Copyright (C) 2022 The Android Open Source Project
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

#ifndef ANDROID_SERVERS_HIDLCAMERA3DEVICE_H
#define ANDROID_SERVERS_HIDLCAMERA3DEVICE_H

#include "../Camera3Device.h"
#include "HidlCamera3OutputUtils.h"

namespace android {


/**
 * CameraDevice for HIDL HAL devices with version CAMERA_DEVICE_API_VERSION_3_0 or higher.
 */
class HidlCamera3Device :
            virtual public hardware::camera::device::V3_5::ICameraDeviceCallback,
            public Camera3Device {
  public:

    explicit HidlCamera3Device(
        std::shared_ptr<CameraServiceProxyWrapper>& cameraServiceProxyWrapper,
        std::shared_ptr<AttributionAndPermissionUtils> attributionAndPermissionUtils,
        const std::string& id, bool overrideForPerfClass, int rotationOverride,
        bool legacyClient = false) :
        Camera3Device(cameraServiceProxyWrapper, attributionAndPermissionUtils, id,
                overrideForPerfClass, rotationOverride, legacyClient) { }

    virtual ~HidlCamera3Device() {}

   /**
     * Helper functions to map between framework and HIDL values
     */
    static hardware::graphics::common::V1_0::PixelFormat mapToPixelFormat(int frameworkFormat);
    static hardware::camera::device::V3_2::DataspaceFlags mapToHidlDataspace(
            android_dataspace dataSpace);
    static hardware::camera::device::V3_2::BufferUsageFlags mapToConsumerUsage(uint64_t usage);
    static hardware::camera::device::V3_2::StreamRotation mapToStreamRotation(
            camera_stream_rotation_t rotation);
    // Returns a negative error code if the passed-in operation mode is not valid.
    static status_t mapToStreamConfigurationMode(camera_stream_configuration_mode_t operationMode,
            /*out*/ hardware::camera::device::V3_2::StreamConfigurationMode *mode);
    static int mapToFrameworkFormat(hardware::graphics::common::V1_0::PixelFormat pixelFormat);
    static android_dataspace mapToFrameworkDataspace(
            hardware::camera::device::V3_2::DataspaceFlags);
    static uint64_t mapConsumerToFrameworkUsage(
            hardware::camera::device::V3_2::BufferUsageFlags usage);
    static uint64_t mapProducerToFrameworkUsage(
            hardware::camera::device::V3_2::BufferUsageFlags usage);

    status_t initialize(sp<CameraProviderManager> manager, const std::string& monitorTags) override;

    /**
     * Implementation of android::hardware::camera::device::V3_5::ICameraDeviceCallback
     */

    hardware::Return<void> processCaptureResult_3_4(
            const hardware::hidl_vec<
                    hardware::camera::device::V3_4::CaptureResult>& results) override;
    hardware::Return<void> processCaptureResult(
            const hardware::hidl_vec<
                    hardware::camera::device::V3_2::CaptureResult>& results) override;
    hardware::Return<void> notify(
            const hardware::hidl_vec<
                    hardware::camera::device::V3_2::NotifyMsg>& msgs) override;

    hardware::Return<void> requestStreamBuffers(
            const hardware::hidl_vec<
                    hardware::camera::device::V3_5::BufferRequest>& bufReqs,
            requestStreamBuffers_cb _hidl_cb) override;

    hardware::Return<void> returnStreamBuffers(
            const hardware::hidl_vec<
                    hardware::camera::device::V3_2::StreamBuffer>& buffers) override;

    status_t switchToOffline(const std::vector<int32_t>& streamsToKeep,
            /*out*/ sp<CameraOfflineSessionBase>* session) override;

    using RequestMetadataQueue = hardware::MessageQueue<uint8_t, hardware::kSynchronizedReadWrite>;

    class HidlHalInterface : public Camera3Device::HalInterface {
     public:
        HidlHalInterface(sp<hardware::camera::device::V3_2::ICameraDeviceSession> &session,
                     std::shared_ptr<RequestMetadataQueue> queue,
                     bool useHalBufManager, bool supportOfflineProcessing);

        virtual IPCTransport getTransportType() const override { return IPCTransport::HIDL; }
        // Returns true if constructed with a valid device or session, and not yet cleared
        virtual bool valid() override;

        // Reset this HalInterface object (does not call close())
        virtual void clear() override;

        // Calls into the HAL interface

        // Caller takes ownership of requestTemplate
        virtual status_t constructDefaultRequestSettings(camera_request_template templateId,
                /*out*/ camera_metadata_t **requestTemplate) override;

        virtual status_t configureStreams(const camera_metadata_t *sessionParams,
                /*inout*/ camera_stream_configuration_t *config,
                const std::vector<uint32_t>& bufferSizes,
                int64_t logId) override;

        // The injection camera configures the streams to hal.
        virtual status_t configureInjectedStreams(
                const camera_metadata_t* sessionParams,
                /*inout*/ camera_stream_configuration_t* config,
                const std::vector<uint32_t>& bufferSizes,
                const CameraMetadata& cameraCharacteristics) override;

        // When the call succeeds, the ownership of acquire fences in requests is transferred to
        // HalInterface. More specifically, the current implementation will send the fence to
        // HAL process and close the FD in cameraserver process. When the call fails, the ownership
        // of the acquire fence still belongs to the caller.
        virtual status_t processBatchCaptureRequests(
                std::vector<camera_capture_request_t*>& requests,
                /*out*/uint32_t* numRequestProcessed) override;
        virtual status_t flush() override;
        virtual status_t dump(int fd) override;
        virtual status_t close() override;

        virtual void signalPipelineDrain(const std::vector<int>& streamIds) override;
        virtual bool isReconfigurationRequired(CameraMetadata& oldSessionParams,
                CameraMetadata& newSessionParams) override;

        virtual status_t repeatingRequestEnd(uint32_t frameNumber,
                const std::vector<int32_t> &streamIds) override;

        status_t switchToOffline(
        const std::vector<int32_t>& streamsToKeep,
        /*out*/hardware::camera::device::V3_6::CameraOfflineSessionInfo* offlineSessionInfo,
        /*out*/sp<hardware::camera::device::V3_6::ICameraOfflineSession>* offlineSession,
        /*out*/camera3::BufferRecords* bufferRecords);

     private:

        // Always valid
        sp<hardware::camera::device::V3_2::ICameraDeviceSession> mHidlSession;
        // Valid if ICameraDeviceSession is @3.3 or newer
        sp<hardware::camera::device::V3_3::ICameraDeviceSession> mHidlSession_3_3;
        // Valid if ICameraDeviceSession is @3.4 or newer
        sp<hardware::camera::device::V3_4::ICameraDeviceSession> mHidlSession_3_4;
        // Valid if ICameraDeviceSession is @3.5 or newer
        sp<hardware::camera::device::V3_5::ICameraDeviceSession> mHidlSession_3_5;
        // Valid if ICameraDeviceSession is @3.6 or newer
        sp<hardware::camera::device::V3_6::ICameraDeviceSession> mHidlSession_3_6;
        // Valid if ICameraDeviceSession is @3.7 or newer
        sp<hardware::camera::device::V3_7::ICameraDeviceSession> mHidlSession_3_7;

        std::shared_ptr<RequestMetadataQueue> mRequestMetadataQueue;

        // The output HIDL request still depends on input camera_capture_request_t
        // Do not free input camera_capture_request_t before output HIDL request
        status_t wrapAsHidlRequest(camera_capture_request_t* in,
                /*out*/hardware::camera::device::V3_2::CaptureRequest* out,
                /*out*/std::vector<native_handle_t*>* handlesCreated,
                /*out*/std::vector<std::pair<int32_t, int32_t>>* inflightBuffers);
    }; // class HidlHalInterface

    class HidlRequestThread : public Camera3Device::RequestThread {
      public:
        HidlRequestThread(wp<Camera3Device> parent,
                sp<camera3::StatusTracker> statusTracker,
                sp<HalInterface> interface,
                const Vector<int32_t>& sessionParamKeys,
                bool useHalBufManager,
                bool supportCameraMute,
                int rotationOverride,
                bool supportSettingsOverride);

        status_t switchToOffline(
                const std::vector<int32_t>& streamsToKeep,
                /*out*/hardware::camera::device::V3_6::CameraOfflineSessionInfo* offlineSessionInfo,
                /*out*/sp<hardware::camera::device::V3_6::ICameraOfflineSession>* offlineSession,
                /*out*/camera3::BufferRecords* bufferRecords);
    }; // class HidlRequestThread

    class HidlCamera3DeviceInjectionMethods : public Camera3DeviceInjectionMethods {
     public:
        // Initialize the injection camera and generate an hal interface.
        status_t injectionInitialize(
                const std::string& injectedCamId, sp<CameraProviderManager> manager,
                const sp<
                    android::hardware::camera::device::V3_2 ::ICameraDeviceCallback>&
                    callback);
        HidlCamera3DeviceInjectionMethods(wp<Camera3Device> parent) :
                Camera3DeviceInjectionMethods(parent) { };
        ~HidlCamera3DeviceInjectionMethods() {}
     private:
        // Backup of the original camera hal result FMQ.
        std::unique_ptr<ResultMetadataQueue> mBackupResultMetadataQueue;

        // FMQ writes the result for the injection camera. Must be guarded by
        // mProcessCaptureResultLock.
        std::unique_ptr<ResultMetadataQueue> mInjectionResultMetadataQueue;

        // Use injection camera hal interface to replace and backup original
        // camera hal interface.
        virtual status_t replaceHalInterface(sp<HalInterface> newHalInterface,
                bool keepBackup) override;
    };

  private:
    template<typename NotifyMsgType>
    hardware::Return<void> notifyHelper(
            const hardware::hidl_vec<NotifyMsgType>& msgs);

    virtual void applyMaxBatchSizeLocked(
            RequestList* requestList,
            const sp<camera3::Camera3OutputStreamInterface>& stream) override;

    virtual status_t injectionCameraInitialize(const std::string &injectCamId,
            sp<CameraProviderManager> manager) override;

    virtual sp<RequestThread> createNewRequestThread(wp<Camera3Device> parent,
                sp<camera3::StatusTracker> statusTracker,
                sp<HalInterface> interface,
                const Vector<int32_t>& sessionParamKeys,
                bool useHalBufManager,
                bool supportCameraMute,
                int rotationOverride,
                bool supportSettingsOverride) override;

    virtual sp<Camera3DeviceInjectionMethods>
            createCamera3DeviceInjectionMethods(wp<Camera3Device>) override;

    // FMQ to write result on. Must be guarded by mProcessCaptureResultLock.
    std::unique_ptr<ResultMetadataQueue> mResultMetadataQueue;

}; // class HidlCamera3Device

}; // namespace android

#endif
