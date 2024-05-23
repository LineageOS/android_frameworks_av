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

#ifndef ANDROID_SERVERS_AIDLCAMERA3DEVICE_H
#define ANDROID_SERVERS_AIDLCAMERA3DEVICE_H

#include "../Camera3Device.h"
#include "AidlCamera3OutputUtils.h"
#include <fmq/AidlMessageQueue.h>

#include <aidl/android/hardware/camera/device/BnCameraDeviceCallback.h>
#include <aidl/android/hardware/camera/device/ICameraDevice.h>
#include <aidl/android/hardware/camera/device/ICameraInjectionSession.h>
namespace android {

using ::aidl::android::hardware::common::fmq::SynchronizedReadWrite;
using ::android::AidlMessageQueue;

/**
 * CameraDevice for AIDL HAL devices.
 */
class AidlCamera3Device :
            public Camera3Device {
  public:

    using AidlRequestMetadataQueue = AidlMessageQueue<int8_t, SynchronizedReadWrite>;
    class AidlCameraDeviceCallbacks;
    friend class AidlCameraDeviceCallbacks;
    explicit AidlCamera3Device(
            std::shared_ptr<CameraServiceProxyWrapper>& cameraServiceProxyWrapper,
            const std::string& id, bool overrideForPerfClass, bool overrideToPortrait,
            bool legacyClient = false);

    virtual ~AidlCamera3Device() { }

    static aidl::android::hardware::graphics::common::PixelFormat mapToAidlPixelFormat(
            int frameworkFormat);
    static aidl::android::hardware::graphics::common::Dataspace mapToAidlDataspace(
            android_dataspace dataSpace);
    static aidl::android::hardware::graphics::common::BufferUsage mapToAidlConsumerUsage(
            uint64_t usage);
    static aidl::android::hardware::camera::device::StreamRotation
            mapToAidlStreamRotation(camera_stream_rotation_t rotation);

    static status_t mapToAidlStreamConfigurationMode(
            camera_stream_configuration_mode_t operationMode,
            aidl::android::hardware::camera::device::StreamConfigurationMode *mode);

    static int mapToFrameworkFormat(
        aidl::android::hardware::graphics::common::PixelFormat pixelFormat);
    static android_dataspace mapToFrameworkDataspace(
            aidl::android::hardware::graphics::common::Dataspace);
    static uint64_t mapConsumerToFrameworkUsage(
            aidl::android::hardware::graphics::common::BufferUsage usage);
    static uint64_t mapProducerToFrameworkUsage(
            aidl::android::hardware::graphics::common::BufferUsage usage);

    virtual status_t switchToOffline(const std::vector<int32_t>& /*streamsToKeep*/,
            /*out*/ sp<CameraOfflineSessionBase>* /*session*/) override;

    status_t initialize(sp<CameraProviderManager> manager, const std::string& monitorTags) override;

    class AidlHalInterface : public Camera3Device::HalInterface {
     public:
        AidlHalInterface(std::shared_ptr<
                aidl::android::hardware::camera::device::ICameraDeviceSession> &session,
                std::shared_ptr<AidlRequestMetadataQueue> queue,
                bool useHalBufManager, bool supportOfflineProcessing,
                bool supportSessionHalBufManager);
        AidlHalInterface(
                std::shared_ptr<aidl::android::hardware::camera::device::ICameraDeviceSession>
                    &deviceSession,
                std::shared_ptr<
                aidl::android::hardware::camera::device::ICameraInjectionSession> &injectionSession,
                std::shared_ptr<AidlRequestMetadataQueue> queue,
                bool useHalBufManager, bool supportOfflineProcessing,
                bool supportSessionHalBufManager);

        virtual IPCTransport getTransportType() const override {return IPCTransport::AIDL; }


        // Returns true if constructed with a valid device or session, and not yet cleared
        virtual bool valid() override;

        // Reset this HalInterface object (does not call close())
        virtual void clear() override;

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

        // Calls into the HAL interface
        virtual status_t flush() override;
        virtual status_t dump(int fd) override;
        virtual status_t close() override;
        virtual void signalPipelineDrain(const std::vector<int>& streamIds) override;
        virtual bool isReconfigurationRequired(CameraMetadata& oldSessionParams,
                CameraMetadata& newSessionParams) override;

        virtual status_t repeatingRequestEnd(uint32_t ,
                const std::vector<int32_t> &) override;

        status_t switchToOffline(
        const std::vector<int32_t>& streamsToKeep,
        /*out*/aidl::android::hardware::camera::device::CameraOfflineSessionInfo*
                offlineSessionInfo,
        /*out*/std::shared_ptr<aidl::android::hardware::camera::device::ICameraOfflineSession>*
                offlineSession,
        /*out*/camera3::BufferRecords* bufferRecords);

     private:

        // Always valid
        std::shared_ptr<aidl::android::hardware::camera::device::ICameraDeviceSession>
                mAidlSession = nullptr;
        //Valid for injection sessions
        std::shared_ptr<aidl::android::hardware::camera::device::ICameraInjectionSession>
                mAidlInjectionSession = nullptr;

        status_t wrapAsAidlRequest(camera_capture_request_t* request,
                /*out*/aidl::android::hardware::camera::device::CaptureRequest* captureRequest,
                /*out*/std::vector<native_handle_t*>* handlesCreated,
                /*out*/std::vector<std::pair<int32_t, int32_t>>* inflightBuffers);

        std::shared_ptr<AidlRequestMetadataQueue> mRequestMetadataQueue;
        bool mSupportSessionHalBufManager = false;
    }; // class AidlHalInterface

    /**
     * Implementation of aidl::android::hardware::camera::device::ICameraDeviceCallback
     */
    ::ndk::ScopedAStatus processCaptureResult(
            const std::vector<aidl::android::hardware::camera::device::CaptureResult>& results);
    ::ndk::ScopedAStatus notify(
            const std::vector<aidl::android::hardware::camera::device::NotifyMsg>& msgs);

    ::ndk::ScopedAStatus requestStreamBuffers(
            const std::vector<aidl::android::hardware::camera::device::BufferRequest>& bufReqs,
            std::vector<aidl::android::hardware::camera::device::StreamBufferRet>* outBuffers,
            aidl::android::hardware::camera::device::BufferRequestStatus* status);

    ::ndk::ScopedAStatus returnStreamBuffers(
            const std::vector<aidl::android::hardware::camera::device::StreamBuffer>& buffers);

    class AidlRequestThread : public Camera3Device::RequestThread {
      public:
        AidlRequestThread(wp<Camera3Device> parent,
                sp<camera3::StatusTracker> statusTracker,
                sp<HalInterface> interface,
                const Vector<int32_t>& sessionParamKeys,
                bool useHalBufManager,
                bool supportCameraMute,
                bool overrideToPortrait,
                bool supportSettingsOverride);

        status_t switchToOffline(
                const std::vector<int32_t>& streamsToKeep,
                /*out*/aidl::android::hardware::camera::device::CameraOfflineSessionInfo*
                        offlineSessionInfo,
                /*out*/std::shared_ptr<
                        aidl::android::hardware::camera::device::ICameraOfflineSession>*
                                offlineSession,
                /*out*/camera3::BufferRecords* bufferRecords);
    }; // class AidlRequestThread

    class AidlCamera3DeviceInjectionMethods : public Camera3DeviceInjectionMethods {
     public:
        // Initialize the injection camera and generate an hal interface.
        status_t injectionInitialize(
                const std::string& injectedCamId, sp<CameraProviderManager> manager,
                const std::shared_ptr<
                    aidl::android::hardware::camera::device::ICameraDeviceCallback>&
                    callback);
        AidlCamera3DeviceInjectionMethods(wp<Camera3Device> parent) :
                Camera3DeviceInjectionMethods(parent) { };
        ~AidlCamera3DeviceInjectionMethods() {}
     private:
        // Backup of the original camera hal result FMQ.
        std::unique_ptr<AidlResultMetadataQueue> mBackupResultMetadataQueue;

        // FMQ writes the result for the injection camera. Must be guarded by
        // mProcessCaptureResultLock.
        std::unique_ptr<AidlResultMetadataQueue> mInjectionResultMetadataQueue;

        // Use injection camera hal interface to replace and backup original
        // camera hal interface.
        virtual status_t replaceHalInterface(sp<HalInterface> newHalInterface,
                bool keepBackup) override;
    };

    // We need a separate class which inherits from AIDL ICameraDeviceCallbacks
    // since we use the ndk backend for AIDL HAL interfaces. The ndk backend of
    // ICameraDeviceCallbacks doesn't support sp<> (since it doesn't inherit
    // from RefBase).
    // As a result we can't write sp<Camera3Device> = new AidlCamera3Device(...).
    // It supports std::shared_ptr instead. Other references to
    // Camera3Device in cameraserver use sp<> widely, so to keep supporting
    // that, we create a new class which will be managed through std::shared_ptr
    // internally by AidlCamera3Device.
    class AidlCameraDeviceCallbacks :
            public aidl::android::hardware::camera::device::BnCameraDeviceCallback {
      public:

        AidlCameraDeviceCallbacks(wp<AidlCamera3Device> parent) : mParent(parent)  { }
        ~AidlCameraDeviceCallbacks() { }
        ::ndk::ScopedAStatus processCaptureResult(
                const std::vector<
                        aidl::android::hardware::camera::device::CaptureResult>& results) override;
        ::ndk::ScopedAStatus notify(
                const std::vector<
                        aidl::android::hardware::camera::device::NotifyMsg>& msgs) override;

        ::ndk::ScopedAStatus requestStreamBuffers(
                const std::vector<
                        aidl::android::hardware::camera::device::BufferRequest>& bufReqs,
                std::vector<aidl::android::hardware::camera::device::StreamBufferRet>* outBuffers,
                aidl::android::hardware::camera::device::BufferRequestStatus* status) override;

        ::ndk::ScopedAStatus returnStreamBuffers(
                const std::vector<
                        aidl::android::hardware::camera::device::StreamBuffer>& buffers) override;

        protected:
        ::ndk::SpAIBinder createBinder() override;

        private:
            wp<AidlCamera3Device> mParent = nullptr;
    };

  private:
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
                bool overrideToPortrait,
                bool supportSettingsOverride) override;

    virtual sp<Camera3DeviceInjectionMethods>
            createCamera3DeviceInjectionMethods(wp<Camera3Device>) override;

    // FMQ to write result on. Must be guarded by mProcessCaptureResultLock.
    std::unique_ptr<AidlResultMetadataQueue> mResultMetadataQueue = nullptr;

    std::shared_ptr<AidlCameraDeviceCallbacks> mCallbacks = nullptr;

    // Whether the batch_size_max field in the high speed configuration actually applied to
    // capture requests.
    bool mBatchSizeLimitEnabled = false;

    // Whether the HAL supports reporting sensor readout timestamp
    bool mSensorReadoutTimestampSupported = true;

}; // class AidlCamera3Device

}; // namespace android

#endif
