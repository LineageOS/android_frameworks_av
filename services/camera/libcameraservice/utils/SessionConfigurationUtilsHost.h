/*
 * Copyright (C) 2021 The Android Open Source Project
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
#ifndef ANDROID_SERVERS_CAMERA_SESSION_CONFIGURATION_UTILS_HOST_H
#define ANDROID_SERVERS_CAMERA_SESSION_CONFIGURATION_UTILS_HOST_H

#include "camera/CameraMetadata.h"

namespace android {
namespace camera3 {
namespace SessionConfigurationUtils {

bool supportsUltraHighResolutionCapture(const CameraMetadata &deviceInfo);

int32_t getAppropriateModeTag(int32_t defaultTag, bool maxResolution = false);

bool getArrayWidthAndHeight(const CameraMetadata *deviceInfo, int32_t arrayTag,
        int32_t *width, int32_t *height);

} // SessionConfigurationUtils
} // camera3
} // android

#endif
