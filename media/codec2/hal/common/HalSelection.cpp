/*
 * Copyright 2023 The Android Open Source Project
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

//#define LOG_NDEBUG 0
#define LOG_TAG "Codec2-HalSelection"
#include <android-base/logging.h>

// NOTE: due to dependency from mainline modules cannot use libsysprop
// #include <android/sysprop/MediaProperties.sysprop.h>
#include <android-base/properties.h>
#include <com_android_media_codec_flags.h>

#include <codec2/common/HalSelection.h>

namespace android {

bool IsCodec2AidlHalSelected() {
    // For new devices with vendor software targeting 202404, we always want to
    // use AIDL if it exists
    constexpr int kAndroidApi202404 = 202404;
    int vendorVersion = ::android::base::GetIntProperty("ro.vendor.api_level", -1);
    if (!com::android::media::codec::flags::provider_->aidl_hal() &&
        vendorVersion < kAndroidApi202404) {
        // Cannot select AIDL if not enabled
        return false;
    }
#if 0
    // NOTE: due to dependency from mainline modules cannot use libsysprop
    using ::android::sysprop::MediaProperties::codec2_hal_selection;
    using ::android::sysprop::MediaProperties::codec2_hal_selection_values;
    constexpr codec2_hal_selection_values AIDL = codec2_hal_selection_values::AIDL;
    constexpr codec2_hal_selection_values HIDL = codec2_hal_selection_values::HIDL;
    codec2_hal_selection_values selection = codec2_hal_selection().value_or(HIDL);
    switch (selection) {
    case AIDL:
        return true;
    case HIDL:
        return false;
    default:
        LOG(FATAL) << "Unexpected codec2 HAL selection value: " << (int)selection;
    }
#else
    std::string selection = ::android::base::GetProperty("media.c2.hal.selection", "hidl");
    if (selection == "aidl") {
        return true;
    } else if (selection == "hidl") {
        return false;
    } else {
        LOG(FATAL) << "Unexpected codec2 HAL selection value: " << selection;
    }
#endif

    return false;
}

}  // namespace android
