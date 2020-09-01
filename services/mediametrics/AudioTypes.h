/*
 * Copyright (C) 2020 The Android Open Source Project
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

#pragma once

#include <string>
#include <unordered_map>

namespace android::mediametrics::types {

// Helper methods that map mediametrics logged strings to integer codes.
// In R we do not use the integer codes, but rather we can use these maps
// to validate correct strings.
const std::unordered_map<std::string, int32_t>& getAudioCallerNameMap();
const std::unordered_map<std::string, int64_t>& getAudioDeviceInMap();
const std::unordered_map<std::string, int64_t>& getAudioDeviceOutMap();
const std::unordered_map<std::string, int32_t>& getAudioThreadTypeMap();
const std::unordered_map<std::string, int32_t>& getAudioTrackTraitsMap();

// Enumeration for the device connection results.
enum DeviceConnectionResult : int32_t {
    DEVICE_CONNECTION_RESULT_SUCCESS = 0,              // Audio delivered
    DEVICE_CONNECTION_RESULT_UNKNOWN = 1,              // Success is unknown.
    DEVICE_CONNECTION_RESULT_JAVA_SERVICE_CANCEL = 2,  // Canceled in Java service
    // Do not modify the constants above after R.  Adding new constants is fine.
};

// Enumeration for all the string translations to integers (generally int32_t) unless noted.
enum AudioEnumCategory {
    CALLER_NAME,
    CONTENT_TYPE,
    ENCODING,
    INPUT_DEVICE,  // int64_t
    INPUT_FLAG,
    OUTPUT_DEVICE, // int64_t
    OUTPUT_FLAG,
    SOURCE_TYPE,
    STREAM_TYPE,
    THREAD_TYPE,
    TRACK_TRAITS,
    USAGE,
};

// Convert a string (or arbitrary S) from an AudioEnumCategory to a particular type.
// This is used to convert log std::strings back to the original type (int32_t or int64_t).
//
// For a string, generally there is a prefix "AUDIO_INPUT_FLAG" or some such that could
// actually indicate the category so the AudioEnumCategory could be superfluous, but
// we use it to find the proper default value in case of an unknown string.
//
// lookup<ENCODING, int32_t>("AUDIO_FORMAT_PCM_16_BIT") -> 1
//
template <AudioEnumCategory C, typename T, typename S>
T lookup(const S &str);

// Helper: Allow using a const char * in lieu of std::string.
template <AudioEnumCategory C, typename T>
T lookup(const char *str) {
    return lookup<C, T, std::string>(str);
}

bool isInputThreadType(const std::string &threadType);

} // namespace android::mediametrics::types
