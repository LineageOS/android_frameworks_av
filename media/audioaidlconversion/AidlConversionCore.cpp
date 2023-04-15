/*
 * Copyright (C) 2023 The Android Open Source Project
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

#define LOG_TAG "AidlConversionCore"
//#define LOG_NDEBUG 0
#include <utils/Log.h>

#include <media/AidlConversionCore.h>
#include <media/AidlConversionCppNdk.h>

namespace aidl {
namespace android {

using MicrophoneDirection = hardware::audio::core::IStreamIn::MicrophoneDirection;
using ::android::BAD_VALUE;
using ::android::OK;
using ::android::status_t;
using ::android::base::unexpected;

ConversionResult<audio_microphone_direction_t>
aidl2legacy_MicrophoneDirection_audio_microphone_direction_t(MicrophoneDirection aidl) {
    switch (aidl) {
        case MicrophoneDirection::UNSPECIFIED:
            return MIC_DIRECTION_UNSPECIFIED;
        case MicrophoneDirection::FRONT:
            return MIC_DIRECTION_FRONT;
        case MicrophoneDirection::BACK:
            return MIC_DIRECTION_BACK;
        case MicrophoneDirection::EXTERNAL:
            return MIC_DIRECTION_EXTERNAL;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<MicrophoneDirection>
legacy2aidl_audio_microphone_direction_t_MicrophoneDirection(audio_microphone_direction_t legacy) {
    switch (legacy) {
        case MIC_DIRECTION_UNSPECIFIED:
            return MicrophoneDirection::UNSPECIFIED;
        case MIC_DIRECTION_FRONT:
            return MicrophoneDirection::FRONT;
        case MIC_DIRECTION_BACK:
            return MicrophoneDirection::BACK;
        case MIC_DIRECTION_EXTERNAL:
            return MicrophoneDirection::EXTERNAL;
    }
    return unexpected(BAD_VALUE);
}

}  // namespace android
}  // aidl
