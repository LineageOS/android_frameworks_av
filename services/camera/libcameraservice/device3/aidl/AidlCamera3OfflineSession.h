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

#ifndef ANDROID_SERVERS_AIDL_CAMERA3OFFLINESESSION_H
#define ANDROID_SERVERS_AIDL_CAMERA3OFFLINESESSION_H

#include <memory>
#include <mutex>

#include <utils/String16.h>

#include "AidlCamera3OutputUtils.h"
#include <aidl/android/hardware/camera/device/BnCameraDeviceCallback.h>
#include <aidl/android/hardware/camera/device/ICameraOfflineSession.h>

#include <fmq/AidlMessageQueue.h>

#include "common/CameraOfflineSessionBase.h"

#include "device3/Camera3BufferManager.h"
#include "device3/Camera3OfflineSession.h"
#include "utils/TagMonitor.h"
#include <camera_metadata_hidden.h>

namespace android {

namespace camera3 {

class Camera3Stream;
class Camera3OutputStreamInterface;
class Camera3StreamInterface;

} // namespace camera3

/**
 * AidlCamera3OfflineSession for offline session defined in AIDL ICameraOfflineSession
 */
class AidlCamera3OfflineSession :
            public Camera3OfflineSession {
  public:

    virtual ~AidlCamera3OfflineSession();

    virtual status_t initialize(wp<NotificationListener> listener) override;

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

    // See explanation for why we need a separate class for this in
    // AidlCamera3Device::AidlCameraDeviceCallbacks in AidlCamera3Device.h
    class AidlCameraDeviceCallbacks :
            public aidl::android::hardware::camera::device::BnCameraDeviceCallback {
      public:

        AidlCameraDeviceCallbacks(wp<AidlCamera3OfflineSession> parent) : mParent(parent)  { }
        ~AidlCameraDeviceCallbacks() {}
        ::ndk::ScopedAStatus processCaptureResult(
                const std::vector<
                        aidl::android::hardware::camera::device::CaptureResult>& results) override;
        ::ndk::ScopedAStatus notify(
                const std::vector<
                        aidl::android::hardware::camera::device::NotifyMsg>& msgs) override;

        ::ndk::ScopedAStatus requestStreamBuffers(
                const std::vector<
                        aidl::android::hardware::camera::device::BufferRequest>& bufReqs,
                std::vector<aidl::android::hardware::camera::device::StreamBufferRet>* out_buffers,
                aidl::android::hardware::camera::device::BufferRequestStatus* _aidl_return
                ) override;

        ::ndk::ScopedAStatus returnStreamBuffers(
                const std::vector<
                        aidl::android::hardware::camera::device::StreamBuffer>& buffers) override;
        protected:

        ::ndk::SpAIBinder createBinder() override;

        private:
            wp<AidlCamera3OfflineSession> mParent = nullptr;
    };

    // initialize by Camera3Device.
    explicit AidlCamera3OfflineSession(
            const std::string& id, const sp<camera3::Camera3Stream>& inputStream,
            const camera3::StreamSet& offlineStreamSet, camera3::BufferRecords&& bufferRecords,
            const camera3::InFlightRequestMap& offlineReqs,
            const Camera3OfflineStates& offlineStates,
            std::shared_ptr<aidl::android::hardware::camera::device::ICameraOfflineSession>
                    offlineSession,
            bool sensorReadoutTimestampSupported)
        : Camera3OfflineSession(id, inputStream, offlineStreamSet, std::move(bufferRecords),
                                offlineReqs, offlineStates),
          mSession(offlineSession),
          mSensorReadoutTimestampSupported(sensorReadoutTimestampSupported) {
            mCallbacks = ndk::SharedRefBase::make<AidlCameraDeviceCallbacks>(this);
    };

    /**
     * End of CameraOfflineSessionBase interface
     */

  private:
    std::shared_ptr<aidl::android::hardware::camera::device::ICameraOfflineSession> mSession;
    // FMQ to write result on. Must be guarded by mProcessCaptureResultLock.
    std::unique_ptr<AidlResultMetadataQueue> mResultMetadataQueue;

    std::shared_ptr<AidlCameraDeviceCallbacks> mCallbacks;

    bool mSensorReadoutTimestampSupported;

    virtual void closeSessionLocked() override;

    virtual void releaseSessionLocked() override;

}; // class AidlCamera3OfflineSession

}; // namespace android

#endif
