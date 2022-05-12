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
#ifndef ANDROID_SERVERS_CAMERA_SESSION_CONFIGURATION_UTILS_HIDL_H
#define ANDROID_SERVERS_CAMERA_SESSION_CONFIGURATION_UTILS_HIDL_H

#include <android/hardware/camera/device/3.8/types.h>
#include <android/hardware/camera/device/3.4/ICameraDeviceSession.h>
#include <android/hardware/camera/device/3.7/ICameraDeviceSession.h>
#include <android/hardware/camera/device/3.8/ICameraDeviceSession.h>

#include <utils/SessionConfigurationUtils.h>

// Convenience methods for constructing binder::Status objects for error returns

namespace android {
namespace camera3 {

namespace SessionConfigurationUtils {

void mapStreamInfo(const camera3::OutputStreamInfo &streamInfo,
        camera3::camera_stream_rotation_t rotation, String8 physicalId, int32_t groupId,
        hardware::camera::device::V3_8::Stream *stream /*out*/);

// utility function to convert AIDL SessionConfiguration to HIDL
// streamConfiguration. Also checks for validity of SessionConfiguration and
// returns a non-ok binder::Status if the passed in session configuration
// isn't valid.
binder::Status
convertToHALStreamCombination(const SessionConfiguration& sessionConfiguration,
        const String8 &cameraId, const CameraMetadata &deviceInfo,
        metadataGetter getMetadata, const std::vector<std::string> &physicalCameraIds,
        hardware::camera::device::V3_8::StreamConfiguration &streamConfiguration,
        bool overrideForPerfClass, bool *earlyExit);

// Utility function to convert a V3_8::StreamConfiguration to
// V3_7::StreamConfiguration. Return false if the original V3_8 configuration cannot
// be used by older version HAL.
bool convertHALStreamCombinationFromV38ToV37(
        hardware::camera::device::V3_7::StreamConfiguration &streamConfigV37,
        const hardware::camera::device::V3_8::StreamConfiguration &streamConfigV38);

// Utility function to convert a V3_7::StreamConfiguration to
// V3_4::StreamConfiguration. Return false if the original V3_7 configuration cannot
// be used by older version HAL.
bool convertHALStreamCombinationFromV37ToV34(
        hardware::camera::device::V3_4::StreamConfiguration &streamConfigV34,
        const hardware::camera::device::V3_7::StreamConfiguration &streamConfigV37);
} // SessionConfigurationUtils
} // camera3
} // android

#endif
