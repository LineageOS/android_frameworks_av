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

#ifndef ANDROID_SERVERS_HIDL_CAMERA3OFFLINESESSION_H
#define ANDROID_SERVERS_HIDL_CAMERA3OFFLINESESSION_H

#include <memory>
#include <mutex>

#include <utils/String16.h>

#include <android/hardware/camera/device/3.6/ICameraOfflineSession.h>

#include <fmq/MessageQueue.h>

#include "HidlCamera3OutputUtils.h"
#include "common/CameraOfflineSessionBase.h"

#include "device3/Camera3BufferManager.h"
#include "device3/Camera3OfflineSession.h"
#include "device3/InFlightRequest.h"

namespace android {

namespace camera3 {

class Camera3Stream;
class Camera3OutputStreamInterface;
class Camera3StreamInterface;

} // namespace camera3

/**
 * HidlCamera3OfflineSession for offline session defined in HIDL ICameraOfflineSession@3.6 or higher
 */
class HidlCamera3OfflineSession :
            public Camera3OfflineSession,
            virtual public hardware::camera::device::V3_5::ICameraDeviceCallback {
  public:

    // initialize by Camera3Device.
    explicit HidlCamera3OfflineSession(const std::string& id,
            const sp<camera3::Camera3Stream>& inputStream,
            const camera3::StreamSet& offlineStreamSet,
            camera3::BufferRecords&& bufferRecords,
            const camera3::InFlightRequestMap& offlineReqs,
            const Camera3OfflineStates& offlineStates,
            sp<hardware::camera::device::V3_6::ICameraOfflineSession> offlineSession) :
      Camera3OfflineSession(id, inputStream, offlineStreamSet, std::move(bufferRecords),
              offlineReqs, offlineStates),
      mSession(offlineSession) {};

    virtual ~HidlCamera3OfflineSession();

    virtual status_t initialize(wp<NotificationListener> listener) override;

    /**
     * HIDL ICameraDeviceCallback interface
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

    /**
     * End of CameraOfflineSessionBase interface
     */

  private:
    sp<hardware::camera::device::V3_6::ICameraOfflineSession> mSession;
    // FMQ to write result on. Must be guarded by mProcessCaptureResultLock.
    std::unique_ptr<ResultMetadataQueue> mResultMetadataQueue;

    virtual void closeSessionLocked() override;

    virtual void releaseSessionLocked() override;
}; // class Camera3OfflineSession

}; // namespace android

#endif
