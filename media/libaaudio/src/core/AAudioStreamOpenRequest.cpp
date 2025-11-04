/*
* Copyright 2025 The Android Open Source Project
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

#define LOG_TAG "AAudioStreamOpenRequest"
//#define LOG_NDEBUG 0

#include "AAudioStreamOpenRequest.h"

namespace aaudio {

// Arbitrary number for maximum limitation, which is around 20s of data for 48kHz playback.
static constexpr int  FRAMES_PER_DATA_CALLBACK_MAX = 1024 * 1024;

AAudioStreamOpenRequest::AAudioStreamOpenRequest(
        const aaudio::AAudioStreamParameters *parameters,
        bool isSharingModeMatchRequired)
        : mSharingModeMatchRequired(isSharingModeMatchRequired) {
    if (parameters != nullptr) {
        AAudioStreamParameters::copyFrom(*parameters);
    }
}

aaudio_result_t AAudioStreamOpenRequest::validate() const {

    // Check for values that are ridiculously out of range to prevent math overflow exploits.
    // The service will do a better check.
    aaudio_result_t result = AAudioStreamParameters::validate();
    if (result != AAUDIO_OK) {
        return result;
    }

    // Prevent ridiculous values from causing problems.
    if (mFramesPerDataCallback != AAUDIO_UNSPECIFIED
        && (mFramesPerDataCallback <= 0
            || mFramesPerDataCallback > FRAMES_PER_DATA_CALLBACK_MAX)) {
        ALOGE("framesPerDataCallback out of range = %d",
              mFramesPerDataCallback);
        return AAUDIO_ERROR_OUT_OF_RANGE;
    }

    return AAUDIO_OK;
}

} // namespace aaudio
