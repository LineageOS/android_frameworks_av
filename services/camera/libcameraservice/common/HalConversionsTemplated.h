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
#ifndef ANDROID_SERVERS_CAMERA_HAL_CONVERSION_TEMPLATED_H
#define ANDROID_SERVERS_CAMERA_HAL_CONVERSION_TEMPLATED_H

#include "common/CameraProviderManager.h"

#include <device3/Camera3StreamInterface.h>

namespace android {

template <class HalCameraDeviceStatus>
HalCameraDeviceStatus mapFrameworkToHalCameraDeviceStatus(
        const CameraDeviceStatus& s)  {
    switch(s) {
        case CameraDeviceStatus::PRESENT:
            return HalCameraDeviceStatus::PRESENT;
        case CameraDeviceStatus::NOT_PRESENT:
            return HalCameraDeviceStatus::NOT_PRESENT;
        case CameraDeviceStatus::ENUMERATING:
            return HalCameraDeviceStatus::ENUMERATING;
    }
    ALOGW("Unexpectedcamera device status code %d", s);
    return HalCameraDeviceStatus::NOT_PRESENT;
}

template <class HalCameraDeviceStatus>
CameraDeviceStatus HalToFrameworkCameraDeviceStatus(
        const HalCameraDeviceStatus& s)  {
    switch(s) {
        case HalCameraDeviceStatus::PRESENT:
            return CameraDeviceStatus::PRESENT;
        case HalCameraDeviceStatus::NOT_PRESENT:
            return CameraDeviceStatus::NOT_PRESENT;
        case HalCameraDeviceStatus::ENUMERATING:
            return CameraDeviceStatus::ENUMERATING;
    }
    ALOGW("Unexpectedcamera device status code %d", s);
    return CameraDeviceStatus::NOT_PRESENT;
}

template <class HalCameraResourceCost>
CameraResourceCost HalToFrameworkResourceCost(
        const HalCameraResourceCost& s)  {
    CameraResourceCost internalResourceCost;
    internalResourceCost.resourceCost = (uint32_t)s.resourceCost;
    for (const auto device : s.conflictingDevices) {
        internalResourceCost.conflictingDevices.emplace_back(device.c_str());
    }
    return internalResourceCost;
}

template <class HalTorchModeStatus>
TorchModeStatus HalToFrameworkTorchModeStatus(
        const HalTorchModeStatus& s)  {
    switch(s) {
        case HalTorchModeStatus::NOT_AVAILABLE:
            return TorchModeStatus::NOT_AVAILABLE;
        case HalTorchModeStatus::AVAILABLE_OFF:
            return TorchModeStatus::AVAILABLE_OFF;
        case HalTorchModeStatus::AVAILABLE_ON:
            return TorchModeStatus::AVAILABLE_ON;
    }
    ALOGW("Unexpectedcamera torch mode status code %d", s);
    return TorchModeStatus::NOT_AVAILABLE;
}

template <class HalCameraDeviceStatus>
 const char* HalDeviceStatusToString(const HalCameraDeviceStatus& s) {
    switch(s) {
        case HalCameraDeviceStatus::NOT_PRESENT:
            return "NOT_PRESENT";
        case HalCameraDeviceStatus::PRESENT:
            return "PRESENT";
        case HalCameraDeviceStatus::ENUMERATING:
            return "ENUMERATING";
    }
    ALOGW("Unexpected HAL device status code %d", s);
    return "UNKNOWN_STATUS";
}

}

#endif
