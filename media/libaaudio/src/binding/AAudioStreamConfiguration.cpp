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

#include "AAudioStreamConfiguration.h"

// go/keep-sorted start
#include <aaudio/AAudio.h>
#include <media/AidlConversion.h>
#include <utils/Log.h>
// go/keep-sorted end

// go/keep-sorted start
#include <stdint.h>
#include <sys/mman.h>
// go/keep-sorted end

using namespace aaudio;

using android::media::audio::common::AudioFormatDescription;

AAudioStreamConfiguration::AAudioStreamConfiguration(const StreamParameters& parcelable) {
    setChannelMask(parcelable.channelMask);
    setSampleRate(parcelable.sampleRate);
    auto deviceIds = android::convertContainer<android::DeviceIdVector>(
            parcelable.deviceIds, android::aidl2legacy_int32_t_audio_port_handle_t);
    if (deviceIds.ok()) {
        setDeviceIds(deviceIds.value());
    } else {
        ALOGE("deviceIds (%s) aidl2legacy conversion failed",
              android::toString(parcelable.deviceIds).c_str());
        android::DeviceIdVector emptyDeviceIds;
        setDeviceIds(emptyDeviceIds);
    }
    static_assert(sizeof(aaudio_sharing_mode_t) == sizeof(parcelable.sharingMode));
    setSharingMode(parcelable.sharingMode);
    auto convFormat = android::aidl2legacy_AudioFormatDescription_audio_format_t(
            parcelable.audioFormat);
    setFormat(convFormat.ok() ? convFormat.value() : AUDIO_FORMAT_INVALID);
    if (!convFormat.ok()) {
        ALOGE("audioFormat (%s) aidl2legacy conversion failed",
              parcelable.hardwareAudioFormat.toString().c_str());
    }
    static_assert(sizeof(aaudio_direction_t) == sizeof(parcelable.direction));
    setDirection(parcelable.direction);
    static_assert(sizeof(audio_usage_t) == sizeof(parcelable.usage));
    setUsage(parcelable.usage);
    static_assert(sizeof(aaudio_content_type_t) == sizeof(parcelable.contentType));
    setContentType(parcelable.contentType);
    setTags(std::set(parcelable.tags.begin(), parcelable.tags.end()));
    static_assert(sizeof(aaudio_spatialization_behavior_t) ==
            sizeof(parcelable.spatializationBehavior));
    setSpatializationBehavior(parcelable.spatializationBehavior);
    setIsContentSpatialized(parcelable.isContentSpatialized);

    static_assert(sizeof(aaudio_input_preset_t) == sizeof(parcelable.inputPreset));
    setInputPreset(parcelable.inputPreset);
    setBufferCapacity(parcelable.bufferCapacity);
    static_assert(
            sizeof(aaudio_allowed_capture_policy_t) == sizeof(parcelable.allowedCapturePolicy));
    setAllowedCapturePolicy(parcelable.allowedCapturePolicy);
    static_assert(sizeof(aaudio_session_id_t) == sizeof(parcelable.sessionId));
    setSessionId(parcelable.sessionId);
    setPrivacySensitive(parcelable.isPrivacySensitive);
    setHardwareSamplesPerFrame(parcelable.hardwareSamplesPerFrame);
    setHardwareSampleRate(parcelable.hardwareSampleRate);
    auto convHardwareFormat = android::aidl2legacy_AudioFormatDescription_audio_format_t(
            parcelable.hardwareAudioFormat);
    setHardwareFormat(convHardwareFormat.ok() ? convHardwareFormat.value() : AUDIO_FORMAT_INVALID);
    if (!convHardwareFormat.ok()) {
        ALOGE("hardwareAudioFormat (%s) aidl2legacy conversion failed",
              parcelable.hardwareAudioFormat.toString().c_str());
    }

    static_assert(sizeof(aaudio_performance_mode_t) == sizeof(parcelable.performanceMode));
    setPerformanceMode(parcelable.performanceMode);
    static_assert(sizeof(audio_port_handle_t) == sizeof(parcelable.portHandle));
    setPortHandle(parcelable.portHandle);
    static_assert(sizeof(audio_io_handle_t) == sizeof(parcelable.ioHandle));
    setIoHandle(parcelable.ioHandle);
}

AAudioStreamConfiguration&
AAudioStreamConfiguration::operator=(const StreamParameters& parcelable) {
    this->~AAudioStreamConfiguration();
    new (this) AAudioStreamConfiguration(parcelable);
    return *this;
}

StreamParameters AAudioStreamConfiguration::parcelable() const {
    StreamParameters result;
    result.channelMask = getChannelMask();
    result.sampleRate = getSampleRate();
    auto deviceIds = android::convertContainer<std::vector<int32_t>>(
            getDeviceIds(), android::legacy2aidl_audio_port_handle_t_int32_t);
    if (deviceIds.ok()) {
        result.deviceIds = deviceIds.value();
    } else {
        ALOGE("deviceIds (%s) legacy2aidl conversion failed",
              android::toString(getDeviceIds()).c_str());
        result.deviceIds = {};
    }
    static_assert(sizeof(aaudio_sharing_mode_t) == sizeof(result.sharingMode));
    result.sharingMode = getSharingMode();
    auto convAudioFormat = android::legacy2aidl_audio_format_t_AudioFormatDescription(getFormat());
    if (convAudioFormat.ok()) {
        result.audioFormat = convAudioFormat.value();
    } else {
        ALOGE("audioFormat (%s) legacy2aidl conversion failed",
              audio_format_to_string(getFormat()));
        result.audioFormat = AudioFormatDescription{};
        result.audioFormat.type =
                android::media::audio::common::AudioFormatType::SYS_RESERVED_INVALID;
    }
    static_assert(sizeof(aaudio_direction_t) == sizeof(result.direction));
    result.direction = getDirection();
    static_assert(sizeof(audio_usage_t) == sizeof(result.usage));
    result.usage = getUsage();
    static_assert(sizeof(aaudio_content_type_t) == sizeof(result.contentType));
    result.contentType = getContentType();
    auto tags = getTags();
    result.tags = std::vector(tags.begin(), tags.end());
    static_assert(
            sizeof(aaudio_spatialization_behavior_t) == sizeof(result.spatializationBehavior));
    result.spatializationBehavior = getSpatializationBehavior();
    result.isContentSpatialized = isContentSpatialized();
    static_assert(sizeof(aaudio_input_preset_t) == sizeof(result.inputPreset));
    result.inputPreset = getInputPreset();
    result.bufferCapacity = getBufferCapacity();
    static_assert(sizeof(aaudio_allowed_capture_policy_t) == sizeof(result.allowedCapturePolicy));
    result.allowedCapturePolicy = getAllowedCapturePolicy();
    static_assert(sizeof(aaudio_session_id_t) == sizeof(result.sessionId));
    result.sessionId = getSessionId();
    result.isPrivacySensitive = isPrivacySensitive();
    result.hardwareSamplesPerFrame = getHardwareSamplesPerFrame();
    result.hardwareSampleRate = getHardwareSampleRate();
    auto convHardwareAudioFormat = android::legacy2aidl_audio_format_t_AudioFormatDescription(
            getHardwareFormat());
    if (convHardwareAudioFormat.ok()) {
        result.hardwareAudioFormat = convHardwareAudioFormat.value();
    } else {
        ALOGE("hardwareAudioFormat (%s) legacy2aidl conversion failed",
              audio_format_to_string(getHardwareFormat()));
        result.hardwareAudioFormat = AudioFormatDescription{};
        result.hardwareAudioFormat.type =
                android::media::audio::common::AudioFormatType::SYS_RESERVED_INVALID;
    }
    static_assert(sizeof(aaudio_performance_mode_t) == sizeof(result.performanceMode));
    result.performanceMode = getPerformanceMode();
    static_assert(sizeof(audio_port_handle_t) == sizeof(result.portHandle));
    result.portHandle = getPortHandle();
    static_assert(sizeof(audio_io_handle_t) == sizeof(result.ioHandle));
    result.ioHandle = getIoHandle();
    return result;
}
