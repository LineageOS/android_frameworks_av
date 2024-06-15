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

#ifndef ANDROID_SERVERS_AIDL_CAMERA3_OUTPUT_UTILS_H
#define ANDROID_SERVERS_AIDL_CAMERA3_OUTPUT_UTILS_H

#include <memory>
#include <mutex>

#include <cutils/native_handle.h>

#include <aidlcommonsupport/NativeHandle.h>
#include <fmq/AidlMessageQueue.h>

#include <common/CameraDeviceBase.h>

#include <aidl/android/hardware/camera/device/ICameraDevice.h>
#include <aidl/android/hardware/camera/device/ICameraDeviceCallback.h>
#include "device3/BufferUtils.h"
#include "device3/InFlightRequest.h"
#include "device3/Camera3Stream.h"
#include "device3/Camera3OutputStreamInterface.h"
#include "device3/Camera3OutputUtils.h"
#include "utils/SessionStatsBuilder.h"
#include "utils/TagMonitor.h"

namespace android {

using ::aidl::android::hardware::common::fmq::SynchronizedReadWrite;
using ::android::AidlMessageQueue;

using AidlResultMetadataQueue = AidlMessageQueue<int8_t, SynchronizedReadWrite>;
namespace camera3 {
    inline aidl::android::hardware::common::NativeHandle dupToAidlIfNotNull(
            const native_handle_t *nh) {
        if (nh == nullptr) {
            return aidl::android::hardware::common::NativeHandle();
        }
        return dupToAidl(nh);
    }

    inline aidl::android::hardware::common::NativeHandle makeToAidlIfNotNull(
            const native_handle_t *nh) {
        if (nh == nullptr) {
            return aidl::android::hardware::common::NativeHandle();
        }
        return makeToAidl(nh);
    }

    /**
     * Helper methods shared between AidlCamera3Device/AidlCamera3OfflineSession for HAL callbacks
     */

    // Camera3Device/Camera3OfflineSession internal states used in notify/processCaptureResult
    // callbacks
    struct AidlCaptureOutputStates : public CaptureOutputStates {
        std::unique_ptr<AidlResultMetadataQueue>& fmq;
    };

    // Handle one capture result. Assume callers hold the lock to serialize all
    // processCaptureResult calls
    void processOneCaptureResultLocked(
            AidlCaptureOutputStates& states,
            const aidl::android::hardware::camera::device::CaptureResult& result,
            const std::vector<aidl::android::hardware::camera::device::PhysicalCameraMetadata>
                    &physicalCameraMetadata);

    void notify(CaptureOutputStates& states,
            const aidl::android::hardware::camera::device::NotifyMsg& msg,
            bool hasReadoutTimestamp);

    void requestStreamBuffers(RequestBufferStates& states,
        const std::vector<aidl::android::hardware::camera::device::BufferRequest>& bufReqs,
        std::vector<::aidl::android::hardware::camera::device::StreamBufferRet>* out_buffers,
        ::aidl::android::hardware::camera::device::BufferRequestStatus* _aidl_return);

    void returnStreamBuffers(ReturnBufferStates& states,
        const std::vector<aidl::android::hardware::camera::device::StreamBuffer>& buffers);

} // namespace camera3

} // namespace android

#endif
