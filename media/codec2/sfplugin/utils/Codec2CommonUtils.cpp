/*
 * Copyright 2018, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//#define LOG_NDEBUG 0
#define LOG_TAG "Codec2BufferUtils"
#define ATRACE_TAG  ATRACE_TAG_VIDEO
#include <utils/Log.h>

#include <android/hardware_buffer.h>
#include <cutils/properties.h>
#include <media/hardware/HardwareAPI.h>
#include <system/graphics.h>

#include <C2Debug.h>

#include "Codec2CommonUtils.h"

namespace android {

bool isAtLeastT() {
    char deviceCodeName[PROP_VALUE_MAX];
    __system_property_get("ro.build.version.codename", deviceCodeName);
    return android_get_device_api_level() >= __ANDROID_API_T__ ||
           !strcmp(deviceCodeName, "Tiramisu");
}

bool isHalPixelFormatSupported(AHardwareBuffer_Format format) {
    // HAL_PIXEL_FORMAT_YCBCR_P010 was added in Android T, return false for older versions
    if (format == (AHardwareBuffer_Format)HAL_PIXEL_FORMAT_YCBCR_P010 && !isAtLeastT()) {
        return false;
    }

    const AHardwareBuffer_Desc desc = {
            .width = 320,
            .height = 240,
            .format = format,
            .layers = 1,
            .usage = AHARDWAREBUFFER_USAGE_CPU_READ_RARELY | AHARDWAREBUFFER_USAGE_CPU_WRITE_OFTEN |
                     AHARDWAREBUFFER_USAGE_GPU_SAMPLED_IMAGE,
            .stride = 0,
            .rfu0 = 0,
            .rfu1 = 0,
    };

    return AHardwareBuffer_isSupported(&desc);
}

}  // namespace android
