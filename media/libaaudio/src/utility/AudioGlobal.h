/*
 * Copyright 2019 The Android Open Source Project
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
#ifndef AAUDIO_AUDIOGLOBAL_H
#define AAUDIO_AUDIOGLOBAL_H

// go/keep-sorted start
#include <aaudio/AAudio.h>
#include <aaudio/AAudioTesting.h>
// go/keep-sorted end

namespace aaudio {

// Internal error codes. Only used by the framework.
enum {
    AAUDIO_INTERNAL_ERROR_BASE = -1000,
    AAUDIO_ERROR_STANDBY,
    AAUDIO_ERROR_ALREADY_CLOSED,

};

static const char AUDIO_ATTRIBUTES_TAGS_SEPARATOR = ';';

aaudio_policy_t AudioGlobal_getMMapPolicy();
aaudio_result_t AudioGlobal_setMMapPolicy(aaudio_policy_t policy);

const char* AudioGlobal_convertFormatToText(aaudio_format_t format);
const char* AudioGlobal_convertDirectionToText(aaudio_direction_t direction);
const char* AudioGlobal_convertPerformanceModeToText(aaudio_performance_mode_t mode);
const char* AudioGlobal_convertPerformanceModeToShortText(aaudio_performance_mode_t mode);
const char* AudioGlobal_convertResultToText(aaudio_result_t returnCode);
const char* AudioGlobal_convertSharingModeToText(aaudio_sharing_mode_t mode);
const char* AudioGlobal_convertStreamStateToText(aaudio_stream_state_t state);

aaudio_policy_t AudioGlobal_getPlatformMMapPolicy(
        AAudio_DeviceType device, aaudio_direction_t direction);
aaudio_policy_t AudioGlobal_getPlatformMMapExclusivePolicy(
        AAudio_DeviceType device, aaudio_direction_t direction);

} // namespace aaudio

#endif  // AAUDIO_AUDIOGLOBAL_H

