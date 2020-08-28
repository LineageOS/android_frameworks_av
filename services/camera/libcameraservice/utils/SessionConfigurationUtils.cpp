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
#include "SessionConfigurationUtils.h"
#include "../api2/CameraDeviceClient.h"

namespace android {

binder::Status
SessionConfigurationUtils::convertToHALStreamCombination(
        const SessionConfiguration& sessionConfiguration,
        const String8 &logicalCameraId, const CameraMetadata &deviceInfo,
        metadataGetter getMetadata, const std::vector<std::string> &physicalCameraIds,
        hardware::camera::device::V3_4::StreamConfiguration &streamConfiguration, bool *earlyExit) {
    // TODO: http://b/148329298 Move the other dependencies from
    // CameraDeviceClient into SessionConfigurationUtils.
    return CameraDeviceClient::convertToHALStreamCombination(sessionConfiguration, logicalCameraId,
            deviceInfo, getMetadata, physicalCameraIds, streamConfiguration, earlyExit);
}

}// namespace android
