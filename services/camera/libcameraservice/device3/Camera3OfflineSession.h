/*
 * Copyright (C) 2019 The Android Open Source Project
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

#ifndef ANDROID_SERVERS_CAMERA3OFFLINESESSION_H
#define ANDROID_SERVERS_CAMERA3OFFLINESESSION_H

#include <utils/String8.h>
#include <utils/String16.h>

#include <android/hardware/camera/device/3.6/ICameraOfflineSession.h>
#include <fmq/MessageQueue.h>

#include "common/CameraOfflineSessionBase.h"

#include "device3/Camera3BufferManager.h"
#include "device3/DistortionMapper.h"
#include "utils/TagMonitor.h"
#include "utils/LatencyHistogram.h"
#include <camera_metadata_hidden.h>

namespace android {

namespace camera3 {

class Camera3Stream;
class Camera3OutputStreamInterface;
class Camera3StreamInterface;

} // namespace camera3

/**
 * Camera3OfflineSession for offline session defined in HIDL ICameraOfflineSession@3.6 or higher
 */
class Camera3OfflineSession :
            public CameraOfflineSessionBase,
            virtual public hardware::camera::device::V3_5::ICameraDeviceCallback {

  public:

    // initialize by Camera3Device. Camera3Device must send all info in separate argument.
    // monitored tags
    // mUseHalBufManager
    // mUsePartialResult
    // mNumPartialResults
    explicit Camera3OfflineSession(const String8& id);

    virtual ~Camera3OfflineSession();

    status_t initialize(
        sp<hardware::camera::device::V3_6::ICameraOfflineSession> hidlSession);

    /**
     * CameraOfflineSessionBase interface
     */
    const String8& getId() const override;

    status_t disconnect() override;

    status_t dump(int fd) override;

    status_t abort() override;

    // methods for capture result passing
    status_t waitForNextFrame(nsecs_t timeout) override;
    status_t getNextResult(CaptureResult *frame) override;

    // TODO: methods for notification (error/idle/finished etc) passing

    /**
     * End of CameraOfflineSessionBase interface
     */

    /**
     * HIDL ICameraDeviceCallback interface
     */

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

    /**
     * End of CameraOfflineSessionBase interface
     */

  private:

    // Camera device ID
    const String8 mId;

}; // class Camera3OfflineSession

}; // namespace android

#endif
