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

#include <media/AudioValidator.h>
#include <cmath>

namespace android {

/** returns true if string is overflow */
template <size_t size>
bool checkStringOverflow(const char (&s)[size]) {
    return strnlen(s, size) >= size;
}

status_t safetyNetLog(status_t status, std::string_view bugNumber) {
    if (status != NO_ERROR && !bugNumber.empty()) {
        android_errorWriteLog(0x534e4554, bugNumber.data()); // SafetyNet logging
    }
    return status;
}

status_t AudioValidator::validateAudioAttributes(
        const audio_attributes_t& attr, std::string_view bugNumber)
{
    status_t status = NO_ERROR;
    const size_t tagsMaxSize = AUDIO_ATTRIBUTES_TAGS_MAX_SIZE;
    if (strnlen(attr.tags, tagsMaxSize) >= tagsMaxSize) {
        status = BAD_VALUE;
    }
    return safetyNetLog(status, bugNumber);
}

status_t AudioValidator::validateEffectDescriptor(
        const effect_descriptor_t& desc, std::string_view bugNumber)
{
    status_t status = NO_ERROR;
    if (checkStringOverflow(desc.name) || checkStringOverflow(desc.implementor)) {
        status = BAD_VALUE;
    }
    return safetyNetLog(status, bugNumber);
}

status_t AudioValidator::validateAudioPortConfig(
        const struct audio_port_config& config, std::string_view bugNumber)
{
    status_t status = NO_ERROR;
    if (config.type == AUDIO_PORT_TYPE_DEVICE &&
        checkStringOverflow(config.ext.device.address)) {
        status = BAD_VALUE;
    }
    return safetyNetLog(status, bugNumber);
}

namespace {

template <typename T, std::enable_if_t<std::is_same<T, struct audio_port>::value
                                    || std::is_same<T, struct audio_port_v7>::value, int> = 0>
static status_t validateAudioPortInternal(const T& port, std::string_view bugNumber = {}) {
    status_t status = NO_ERROR;
    if (checkStringOverflow(port.name)) {
        status = BAD_VALUE;
    }
    if (AudioValidator::validateAudioPortConfig(port.active_config) != NO_ERROR) {
        status = BAD_VALUE;
    }
    if (port.type == AUDIO_PORT_TYPE_DEVICE &&
        checkStringOverflow(port.ext.device.address)) {
        status = BAD_VALUE;
    }
    return safetyNetLog(status, bugNumber);
}

} // namespace

status_t AudioValidator::validateAudioPort(
        const struct audio_port& port, std::string_view bugNumber)
{
    return validateAudioPortInternal(port, bugNumber);
}

status_t AudioValidator::validateAudioPort(
        const struct audio_port_v7& port, std::string_view bugNumber)
{
    return validateAudioPortInternal(port, bugNumber);
}

/** returns BAD_VALUE if sanitization was required. */
status_t AudioValidator::validateAudioPatch(
        const struct audio_patch& patch, std::string_view bugNumber)
{
    status_t status = NO_ERROR;
    if (patch.num_sources > AUDIO_PATCH_PORTS_MAX) {
        status = BAD_VALUE;
    }
    if (patch.num_sinks > AUDIO_PATCH_PORTS_MAX) {
        status = BAD_VALUE;
    }
    for (size_t i = 0; i < patch.num_sources; i++) {
        if (validateAudioPortConfig(patch.sources[i]) != NO_ERROR) {
            status = BAD_VALUE;
        }
    }
    for (size_t i = 0; i < patch.num_sinks; i++) {
        if (validateAudioPortConfig(patch.sinks[i]) != NO_ERROR) {
            status = BAD_VALUE;
        }
    }
    return safetyNetLog(status, bugNumber);
}

/* static */
status_t AudioValidator::validateAudioDescriptionMixLevel(float leveldB)
{
    constexpr float MAX_AUDIO_DESCRIPTION_MIX_LEVEL = 48.f;
    return std::isnan(leveldB) || leveldB > MAX_AUDIO_DESCRIPTION_MIX_LEVEL ? BAD_VALUE : OK;
}

/* static */
status_t AudioValidator::validateDualMonoMode(audio_dual_mono_mode_t dualMonoMode)
{
    switch (dualMonoMode) {
        case AUDIO_DUAL_MONO_MODE_OFF:
        case AUDIO_DUAL_MONO_MODE_LR:
        case AUDIO_DUAL_MONO_MODE_LL:
        case AUDIO_DUAL_MONO_MODE_RR:
        return OK;
    }
    return BAD_VALUE;
}

/* static */
status_t AudioValidator::validatePlaybackRateFallbackMode(
        audio_timestretch_fallback_mode_t fallbackMode)
{
    switch (fallbackMode) {
        case AUDIO_TIMESTRETCH_FALLBACK_CUT_REPEAT:
            // This is coarse sounding timestretching used for internal debugging,
            // not intended for general use.
            break; // warning if not listed.
        case AUDIO_TIMESTRETCH_FALLBACK_DEFAULT:
        case AUDIO_TIMESTRETCH_FALLBACK_MUTE:
        case AUDIO_TIMESTRETCH_FALLBACK_FAIL:
            return OK;
    }
    return BAD_VALUE;
}

/* static */
status_t AudioValidator::validatePlaybackRateStretchMode(
        audio_timestretch_stretch_mode_t stretchMode)
{
    switch (stretchMode) {
        case AUDIO_TIMESTRETCH_STRETCH_DEFAULT:
        case AUDIO_TIMESTRETCH_STRETCH_VOICE:
            return OK;
    }
    return BAD_VALUE;
}

/* static */
status_t AudioValidator::validatePlaybackRate(
        const audio_playback_rate_t& playbackRate)
{
    if (playbackRate.mSpeed < 0.f || playbackRate.mPitch < 0.f) return BAD_VALUE;
    return validatePlaybackRateFallbackMode(playbackRate.mFallbackMode) ?:
            validatePlaybackRateStretchMode(playbackRate.mStretchMode);
}

}; // namespace android
