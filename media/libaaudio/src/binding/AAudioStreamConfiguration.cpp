/*
 * Copyright 2016 The Android Open Source Project
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

#define LOG_TAG "AAudioStreamConfiguration"
//#define LOG_NDEBUG 0
#include <utils/Log.h>

#include <stdint.h>

#include <sys/mman.h>
#include <aaudio/AAudio.h>

#include "binding/AAudioStreamConfiguration.h"

using namespace aaudio;

using android::media::audio::common::AudioFormat;

AAudioStreamConfiguration::AAudioStreamConfiguration(const StreamParameters& parcelable) {
    setSamplesPerFrame(parcelable.samplesPerFrame);
    setSampleRate(parcelable.sampleRate);
    setDeviceId(parcelable.deviceId);
    static_assert(sizeof(aaudio_sharing_mode_t) == sizeof(parcelable.sharingMode));
    setSharingMode(parcelable.sharingMode);
    static_assert(sizeof(audio_format_t) == sizeof(parcelable.audioFormat));
    setFormat(static_cast<audio_format_t>(parcelable.audioFormat));
    static_assert(sizeof(aaudio_direction_t) == sizeof(parcelable.direction));
    setDirection(parcelable.direction);
    static_assert(sizeof(audio_usage_t) == sizeof(parcelable.usage));
    setUsage(parcelable.usage);
    static_assert(sizeof(aaudio_content_type_t) == sizeof(parcelable.contentType));
    setContentType(parcelable.contentType);
    static_assert(sizeof(aaudio_input_preset_t) == sizeof(parcelable.inputPreset));
    setInputPreset(parcelable.inputPreset);
    setBufferCapacity(parcelable.bufferCapacity);
    static_assert(
            sizeof(aaudio_allowed_capture_policy_t) == sizeof(parcelable.allowedCapturePolicy));
    setAllowedCapturePolicy(parcelable.allowedCapturePolicy);
    static_assert(sizeof(aaudio_session_id_t) == sizeof(parcelable.sessionId));
    setSessionId(parcelable.sessionId);
    setPrivacySensitive(parcelable.isPrivacySensitive);
}

AAudioStreamConfiguration&
AAudioStreamConfiguration::operator=(const StreamParameters& parcelable) {
    this->~AAudioStreamConfiguration();
    new (this) AAudioStreamConfiguration(parcelable);
    return *this;
}

StreamParameters AAudioStreamConfiguration::parcelable() const {
    StreamParameters result;
    result.samplesPerFrame = getSamplesPerFrame();
    result.sampleRate = getSampleRate();
    result.deviceId = getDeviceId();
    static_assert(sizeof(aaudio_sharing_mode_t) == sizeof(result.sharingMode));
    result.sharingMode = getSharingMode();
    static_assert(sizeof(audio_format_t) == sizeof(result.audioFormat));
    result.audioFormat = static_cast<AudioFormat>(getFormat());
    static_assert(sizeof(aaudio_direction_t) == sizeof(result.direction));
    result.direction = getDirection();
    static_assert(sizeof(audio_usage_t) == sizeof(result.usage));
    result.usage = getUsage();
    static_assert(sizeof(aaudio_content_type_t) == sizeof(result.contentType));
    result.contentType = getContentType();
    static_assert(sizeof(aaudio_input_preset_t) == sizeof(result.inputPreset));
    result.inputPreset = getInputPreset();
    result.bufferCapacity = getBufferCapacity();
    static_assert(sizeof(aaudio_allowed_capture_policy_t) == sizeof(result.allowedCapturePolicy));
    result.allowedCapturePolicy = getAllowedCapturePolicy();
    static_assert(sizeof(aaudio_session_id_t) == sizeof(result.sessionId));
    result.sessionId = getSessionId();
    result.isPrivacySensitive = isPrivacySensitive();
    return result;
}
