/*
 * Copyright (C) 2019 The Android Open Source Project
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
#include <aaudio/AAudio.h>
#include <aaudio/AAudioTesting.h>

#include "AudioGlobal.h"

/******************************************
 * Static globals.
 */
namespace aaudio {

static aaudio_policy_t g_MMapPolicy = AAUDIO_UNSPECIFIED;

aaudio_policy_t AudioGlobal_getMMapPolicy() {
  return g_MMapPolicy;
}

aaudio_result_t AudioGlobal_setMMapPolicy(aaudio_policy_t policy) {
    aaudio_result_t result = AAUDIO_OK;
    switch(policy) {
        case AAUDIO_UNSPECIFIED:
        case AAUDIO_POLICY_NEVER:
        case AAUDIO_POLICY_AUTO:
        case AAUDIO_POLICY_ALWAYS:
            g_MMapPolicy = policy;
            break;
        default:
            result = AAUDIO_ERROR_ILLEGAL_ARGUMENT;
            break;
    }
    return result;
}

#define AAUDIO_CASE_ENUM(name) case name: return #name

const char* AudioGlobal_convertResultToText(aaudio_result_t returnCode) {
    switch (returnCode) {
        AAUDIO_CASE_ENUM(AAUDIO_OK);
        AAUDIO_CASE_ENUM(AAUDIO_ERROR_DISCONNECTED);
        AAUDIO_CASE_ENUM(AAUDIO_ERROR_ILLEGAL_ARGUMENT);
        // reserved
        AAUDIO_CASE_ENUM(AAUDIO_ERROR_INTERNAL);
        AAUDIO_CASE_ENUM(AAUDIO_ERROR_INVALID_STATE);
        // reserved
        // reserved
        AAUDIO_CASE_ENUM(AAUDIO_ERROR_INVALID_HANDLE);
         // reserved
        AAUDIO_CASE_ENUM(AAUDIO_ERROR_UNIMPLEMENTED);
        AAUDIO_CASE_ENUM(AAUDIO_ERROR_UNAVAILABLE);
        AAUDIO_CASE_ENUM(AAUDIO_ERROR_NO_FREE_HANDLES);
        AAUDIO_CASE_ENUM(AAUDIO_ERROR_NO_MEMORY);
        AAUDIO_CASE_ENUM(AAUDIO_ERROR_NULL);
        AAUDIO_CASE_ENUM(AAUDIO_ERROR_TIMEOUT);
        AAUDIO_CASE_ENUM(AAUDIO_ERROR_WOULD_BLOCK);
        AAUDIO_CASE_ENUM(AAUDIO_ERROR_INVALID_FORMAT);
        AAUDIO_CASE_ENUM(AAUDIO_ERROR_OUT_OF_RANGE);
        AAUDIO_CASE_ENUM(AAUDIO_ERROR_NO_SERVICE);
        AAUDIO_CASE_ENUM(AAUDIO_ERROR_INVALID_RATE);
    }
    return "Unrecognized";
}

const char* AudioGlobal_convertFormatToText(aaudio_format_t format) {
      switch (format) {
        AAUDIO_CASE_ENUM(AAUDIO_FORMAT_UNSPECIFIED);
        AAUDIO_CASE_ENUM(AAUDIO_FORMAT_INVALID);
        AAUDIO_CASE_ENUM(AAUDIO_FORMAT_PCM_I16);
        AAUDIO_CASE_ENUM(AAUDIO_FORMAT_PCM_FLOAT);
    }
    return "Unrecognized";
}

const char* AudioGlobal_convertDirectionToText(aaudio_direction_t direction) {
      switch (direction) {
        AAUDIO_CASE_ENUM(AAUDIO_DIRECTION_INPUT);
        AAUDIO_CASE_ENUM(AAUDIO_DIRECTION_OUTPUT);
    }
    return "Unrecognized";
}

const char* AudioGlobal_convertPerformanceModeToText(aaudio_performance_mode_t mode) {
      switch (mode) {
        AAUDIO_CASE_ENUM(AAUDIO_PERFORMANCE_MODE_POWER_SAVING);
        AAUDIO_CASE_ENUM(AAUDIO_PERFORMANCE_MODE_NONE);
        AAUDIO_CASE_ENUM(AAUDIO_PERFORMANCE_MODE_LOW_LATENCY);
    }
    return "Unrecognized";
}

const char* AudioGlobal_convertSharingModeToText(aaudio_sharing_mode_t mode) {
      switch (mode) {
        AAUDIO_CASE_ENUM(AAUDIO_SHARING_MODE_SHARED);
        AAUDIO_CASE_ENUM(AAUDIO_SHARING_MODE_EXCLUSIVE);
    }
    return "Unrecognized";
}

const char* AudioGlobal_convertStreamStateToText(aaudio_stream_state_t state) {
      switch (state) {
        AAUDIO_CASE_ENUM(AAUDIO_STREAM_STATE_UNINITIALIZED);
        AAUDIO_CASE_ENUM(AAUDIO_STREAM_STATE_UNKNOWN);
        AAUDIO_CASE_ENUM(AAUDIO_STREAM_STATE_OPEN);
        AAUDIO_CASE_ENUM(AAUDIO_STREAM_STATE_STARTING);
        AAUDIO_CASE_ENUM(AAUDIO_STREAM_STATE_STARTED);
        AAUDIO_CASE_ENUM(AAUDIO_STREAM_STATE_PAUSING);
        AAUDIO_CASE_ENUM(AAUDIO_STREAM_STATE_PAUSED);
        AAUDIO_CASE_ENUM(AAUDIO_STREAM_STATE_FLUSHING);
        AAUDIO_CASE_ENUM(AAUDIO_STREAM_STATE_FLUSHED);
        AAUDIO_CASE_ENUM(AAUDIO_STREAM_STATE_STOPPING);
        AAUDIO_CASE_ENUM(AAUDIO_STREAM_STATE_STOPPED);
        AAUDIO_CASE_ENUM(AAUDIO_STREAM_STATE_CLOSING);
        AAUDIO_CASE_ENUM(AAUDIO_STREAM_STATE_CLOSED);
        AAUDIO_CASE_ENUM(AAUDIO_STREAM_STATE_DISCONNECTED);
    }
    return "Unrecognized";
}

#undef AAUDIO_CASE_ENUM

}  // namespace aaudio
