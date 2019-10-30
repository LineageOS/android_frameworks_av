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

#define LOG_TAG "Camera3-OffLnSsn"
#define ATRACE_TAG ATRACE_TAG_CAMERA
//#define LOG_NDEBUG 0
//#define LOG_NNDEBUG 0  // Per-frame verbose logging

#ifdef LOG_NNDEBUG
#define ALOGVV(...) ALOGV(__VA_ARGS__)
#else
#define ALOGVV(...) ((void)0)
#endif

#include <inttypes.h>

#include <utils/Trace.h>

#include "device3/Camera3OfflineSession.h"
#include "device3/Camera3OutputStream.h"
#include "device3/Camera3InputStream.h"
#include "device3/Camera3SharedOutputStream.h"

using namespace android::camera3;
using namespace android::hardware::camera;

namespace android {

Camera3OfflineSession::Camera3OfflineSession(const String8 &id):
        mId(id)
{
    ATRACE_CALL();
    ALOGV("%s: Created offline session for camera %s", __FUNCTION__, mId.string());
}

Camera3OfflineSession::~Camera3OfflineSession()
{
    ATRACE_CALL();
    ALOGV("%s: Tearing down offline session for camera id %s", __FUNCTION__, mId.string());
}

const String8& Camera3OfflineSession::getId() const {
    return mId;
}

status_t Camera3OfflineSession::initialize(
        sp<hardware::camera::device::V3_6::ICameraOfflineSession> /*hidlSession*/) {
    ATRACE_CALL();
    return OK;
}

status_t Camera3OfflineSession::dump(int /*fd*/) {
    ATRACE_CALL();
    return OK;
}

status_t Camera3OfflineSession::abort() {
    ATRACE_CALL();
    return OK;
}

status_t Camera3OfflineSession::disconnect() {
    ATRACE_CALL();
    return OK;
}

status_t Camera3OfflineSession::waitForNextFrame(nsecs_t /*timeout*/) {
    ATRACE_CALL();
    return OK;
}

status_t Camera3OfflineSession::getNextResult(CaptureResult* /*frame*/) {
    ATRACE_CALL();
    return OK;
}

hardware::Return<void> Camera3OfflineSession::processCaptureResult_3_4(
        const hardware::hidl_vec<
                hardware::camera::device::V3_4::CaptureResult>& /*results*/) {
    return hardware::Void();
}

hardware::Return<void> Camera3OfflineSession::processCaptureResult(
        const hardware::hidl_vec<
                hardware::camera::device::V3_2::CaptureResult>& /*results*/) {
    return hardware::Void();
}

hardware::Return<void> Camera3OfflineSession::notify(
        const hardware::hidl_vec<hardware::camera::device::V3_2::NotifyMsg>& /*msgs*/) {
    return hardware::Void();
}

hardware::Return<void> Camera3OfflineSession::requestStreamBuffers(
        const hardware::hidl_vec<hardware::camera::device::V3_5::BufferRequest>& /*bufReqs*/,
        requestStreamBuffers_cb /*_hidl_cb*/) {
    return hardware::Void();
}

hardware::Return<void> Camera3OfflineSession::returnStreamBuffers(
        const hardware::hidl_vec<hardware::camera::device::V3_2::StreamBuffer>& /*buffers*/) {
    return hardware::Void();
}

}; // namespace android
