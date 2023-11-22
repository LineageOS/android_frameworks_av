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
#include <android-base/properties.h>
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

static bool isP010Allowed() {
    // The first SDK the device shipped with.
    static const int32_t kProductFirstApiLevel =
        base::GetIntProperty<int32_t>("ro.product.first_api_level", 0);

    // GRF devices (introduced in Android 11) list the first and possibly the current api levels
    // to signal which VSR requirements they conform to even if the first device SDK was higher.
    static const int32_t kBoardFirstApiLevel =
        base::GetIntProperty<int32_t>("ro.board.first_api_level", 0);

    // Some devices that launched prior to Android S may not support P010 correctly, even
    // though they may advertise it as supported.
    if (kProductFirstApiLevel != 0 && kProductFirstApiLevel < __ANDROID_API_S__) {
        return false;
    }

    if (kBoardFirstApiLevel != 0 && kBoardFirstApiLevel < __ANDROID_API_S__) {
        return false;
    }

    static const int32_t kBoardApiLevel =
        base::GetIntProperty<int32_t>("ro.board.api_level", 0);

    // For non-GRF devices, use the first SDK version by the product.
    static const int32_t kFirstApiLevel =
        kBoardApiLevel != 0 ? kBoardApiLevel :
        kBoardFirstApiLevel != 0 ? kBoardFirstApiLevel :
        kProductFirstApiLevel;

    return kFirstApiLevel >= __ANDROID_API_T__;
}

bool isHalPixelFormatSupported(AHardwareBuffer_Format format) {
    // HAL_PIXEL_FORMAT_YCBCR_P010 requirement was added in T VSR, although it could have been
    // supported prior to this.
    //
    // Unfortunately, we cannot detect if P010 is properly supported using AHardwareBuffer
    // API alone. For now limit P010 to devices that launched with Android T or known to conform
    // to Android T VSR (as opposed to simply limiting to a T vendor image).
    if (format == (AHardwareBuffer_Format)HAL_PIXEL_FORMAT_YCBCR_P010 &&
            !isP010Allowed()) {
        return false;
    }

    // Default scenario --- the consumer is display or GPU
    const AHardwareBuffer_Desc desc = {
            .width = 320,
            .height = 240,
            .format = format,
            .layers = 1,
            .usage = AHARDWAREBUFFER_USAGE_CPU_READ_RARELY |
                     AHARDWAREBUFFER_USAGE_CPU_WRITE_OFTEN |
                     AHARDWAREBUFFER_USAGE_GPU_SAMPLED_IMAGE |
                     AHARDWAREBUFFER_USAGE_COMPOSER_OVERLAY,
            .stride = 0,
            .rfu0 = 0,
            .rfu1 = 0,
    };

    // The consumer is a HW encoder
    const AHardwareBuffer_Desc descHwEncoder = {
            .width = 320,
            .height = 240,
            .format = format,
            .layers = 1,
            .usage = AHARDWAREBUFFER_USAGE_CPU_READ_RARELY |
                     AHARDWAREBUFFER_USAGE_CPU_WRITE_OFTEN |
                     AHARDWAREBUFFER_USAGE_GPU_SAMPLED_IMAGE |
                     AHARDWAREBUFFER_USAGE_COMPOSER_OVERLAY |
                     AHARDWAREBUFFER_USAGE_VIDEO_ENCODE,
            .stride = 0,
            .rfu0 = 0,
            .rfu1 = 0,
    };

    // The consumer is a SW encoder
    const AHardwareBuffer_Desc descSwEncoder = {
            .width = 320,
            .height = 240,
            .format = format,
            .layers = 1,
            .usage = AHARDWAREBUFFER_USAGE_CPU_READ_OFTEN |
                     AHARDWAREBUFFER_USAGE_CPU_WRITE_OFTEN |
                     AHARDWAREBUFFER_USAGE_GPU_SAMPLED_IMAGE |
                     AHARDWAREBUFFER_USAGE_COMPOSER_OVERLAY,
            .stride = 0,
            .rfu0 = 0,
            .rfu1 = 0,
    };

    return AHardwareBuffer_isSupported(&desc)
            && AHardwareBuffer_isSupported(&descHwEncoder)
            && AHardwareBuffer_isSupported(&descSwEncoder);
}

}  // namespace android
