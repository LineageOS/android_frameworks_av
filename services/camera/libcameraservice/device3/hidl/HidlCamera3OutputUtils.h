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

#ifndef ANDROID_SERVERS_HIDL_CAMERA3_OUTPUT_UTILS_H
#define ANDROID_SERVERS_HIDL_CAMERA3_OUTPUT_UTILS_H

#include <memory>
#include <mutex>

#include <cutils/native_handle.h>

#include <fmq/MessageQueue.h>

#include <common/CameraDeviceBase.h>

#include <android/hardware/camera/device/3.5/ICameraDeviceCallback.h>

#include "device3/BufferUtils.h"
#include "device3/InFlightRequest.h"
#include "device3/Camera3Stream.h"
#include "device3/Camera3OutputUtils.h"

namespace android {

using ResultMetadataQueue = hardware::MessageQueue<uint8_t, hardware::kSynchronizedReadWrite>;

namespace camera3 {

    /**
     * Helper methods shared between HidlCamera3Device/HidlCamera3OfflineSession for HAL callbacks
     */
    // Camera3Device/Camera3OfflineSession internal states used in notify/processCaptureResult
    // callbacks
    struct HidlCaptureOutputStates : public CaptureOutputStates {
        std::unique_ptr<ResultMetadataQueue>& fmq;
    };

    // Handle one capture result. Assume callers hold the lock to serialize all
    // processCaptureResult calls
    void processOneCaptureResultLocked(
            HidlCaptureOutputStates& states,
            const hardware::camera::device::V3_2::CaptureResult& result,
            const hardware::hidl_vec<
                    hardware::camera::device::V3_4::PhysicalCameraMetadata>
                            &physicalCameraMetadata);

    // Handle one notify message
    void notify(CaptureOutputStates& states,
            const hardware::camera::device::V3_2::NotifyMsg& msg);
    void requestStreamBuffers(RequestBufferStates& states,
            const hardware::hidl_vec<hardware::camera::device::V3_5::BufferRequest>& bufReqs,
            hardware::camera::device::V3_5::ICameraDeviceCallback::requestStreamBuffers_cb
                    _hidl_cb);
    void returnStreamBuffers(ReturnBufferStates& states,
            const hardware::hidl_vec<hardware::camera::device::V3_2::StreamBuffer>& buffers);

} // namespace camera3

} // namespace android

#endif
