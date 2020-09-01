/*
 * Copyright (C) 2020 The Android Open Source Project
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
#ifndef ANDROID_SERVERS_CAMERA_SESSION_CONFIGURATION_UTILS_H
#define ANDROID_SERVERS_CAMERA_SESSION_CONFIGURATION_UTILS_H

#include <android/hardware/camera2/BnCameraDeviceUser.h>
#include <android/hardware/camera2/ICameraDeviceCallbacks.h>
#include <camera/camera2/OutputConfiguration.h>
#include <camera/camera2/SessionConfiguration.h>
#include <camera/camera2/SubmitInfo.h>
#include <android/hardware/camera/device/3.4/ICameraDeviceSession.h>

#include <stdint.h>

namespace android {

typedef std::function<CameraMetadata (const String8 &)> metadataGetter;

class SessionConfigurationUtils {
public:
    // utility function to convert AIDL SessionConfiguration to HIDL
    // streamConfiguration. Also checks for validity of SessionConfiguration and
    // returns a non-ok binder::Status if the passed in session configuration
    // isn't valid.
    static binder::Status
    convertToHALStreamCombination(const SessionConfiguration& sessionConfiguration,
            const String8 &cameraId, const CameraMetadata &deviceInfo,
            metadataGetter getMetadata, const std::vector<std::string> &physicalCameraIds,
            hardware::camera::device::V3_4::StreamConfiguration &streamConfiguration,
            bool *earlyExit);
};

} // android
#endif
