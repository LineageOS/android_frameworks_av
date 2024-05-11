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


static bool isAtLeast(int version, const std::string codeName) {
    static std::once_flag sCheckOnce;
    static std::string sDeviceCodeName;
    static int sDeviceApiLevel;
    std::call_once(sCheckOnce, [&](){
        sDeviceCodeName = base::GetProperty("ro.build.version.codename", "");
        sDeviceApiLevel = android_get_device_api_level();
    });
    return sDeviceApiLevel >= version || sDeviceCodeName == codeName;
}

bool isAtLeastT() {
    return isAtLeast(__ANDROID_API_T__, "Tiramisu");
}

bool isAtLeastU() {
    return isAtLeast(__ANDROID_API_U__, "UpsideDownCake");
}

bool isAtLeastV() {
    return isAtLeast(__ANDROID_API_V__, "VanillaIceCream");
}

static bool isP010Allowed() {
    // The Vendor API level which is min(ro.product.first_api_level, ro.board.[first_]api_level).
    // This is the api level to which VSR requirement the device conform.
    static const int32_t kVendorApiLevel =
        base::GetIntProperty<int32_t>("ro.vendor.api_level", 0);

    return kVendorApiLevel >= __ANDROID_API_T__;
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
    const AHardwareBuffer_Desc consumableForDisplayOrGpu = {
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
    const AHardwareBuffer_Desc consumableForHwEncoder = {
            .width = 320,
            .height = 240,
            .format = format,
            .layers = 1,
            .usage = AHARDWAREBUFFER_USAGE_CPU_READ_RARELY |
                     AHARDWAREBUFFER_USAGE_CPU_WRITE_OFTEN |
                     AHARDWAREBUFFER_USAGE_GPU_SAMPLED_IMAGE |
                     AHARDWAREBUFFER_USAGE_VIDEO_ENCODE,
            .stride = 0,
            .rfu0 = 0,
            .rfu1 = 0,
    };

    // The consumer is a SW encoder
    const AHardwareBuffer_Desc consumableForSwEncoder = {
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
    // Some devices running versions prior to Android U aren't guaranteed to advertise support
    // for some color formats when the consumer is an encoder. Hence limit these checks to
    // Android U and beyond.
    if (isAtLeastU()) {
        return AHardwareBuffer_isSupported(&consumableForDisplayOrGpu)
                && AHardwareBuffer_isSupported(&consumableForHwEncoder)
                && AHardwareBuffer_isSupported(&consumableForSwEncoder);
    } else {
        return AHardwareBuffer_isSupported(&consumableForDisplayOrGpu);
    }
}

}  // namespace android
