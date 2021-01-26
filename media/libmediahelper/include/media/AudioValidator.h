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

#ifndef ANDROID_AUDIO_VALIDATOR_H_
#define ANDROID_AUDIO_VALIDATOR_H_

#include <system/audio.h>
#include <system/audio_effect.h>
#include <utils/Errors.h>
#include <utils/Log.h>

#include <string_view>

namespace android {

/**
 * AudioValidator is a class to validate audio data in binder call. NO_ERROR will be returned only
 * when there is no error with the data.
 */
class AudioValidator {
public:
    /**
     * Return NO_ERROR only when there is no error with the given audio attributes.
     * Otherwise, return BAD_VALUE.
     */
    static status_t validateAudioAttributes(
            const audio_attributes_t& attr, std::string_view bugNumber = {});

    /**
     * Return NO_ERROR only when there is no error with the given effect descriptor.
     * Otherwise, return BAD_VALUE.
     */
    static status_t validateEffectDescriptor(
            const effect_descriptor_t& desc, std::string_view bugNumber = {});

    /**
     * Return NO_ERROR only when there is no error with the given audio port config.
     * Otherwise, return BAD_VALUE.
     */
    static status_t validateAudioPortConfig(
            const struct audio_port_config& config, std::string_view bugNumber = {});

    /**
     * Return NO_ERROR only when there is no error with the given audio port.
     * Otherwise, return BAD_VALUE.
     */
    static status_t validateAudioPort(
            const struct audio_port& port, std::string_view bugNumber = {});

    /**
     * Return NO_ERROR only when there is no error with the given audio_port_v7.
     * Otherwise, return BAD_VALUE.
     */
    static status_t validateAudioPort(
            const struct audio_port_v7& port, std::string_view bugNumber = {});

    /**
     * Return NO_ERROR only when there is no error with the given audio patch.
     * Otherwise, return BAD_VALUE.
     */
    static status_t validateAudioPatch(
            const struct audio_patch& patch, std::string_view bugNumber = {});

    /**
     * Return NO_ERROR if leveldB is acceptable, otherwise BAD_VALUE.
     */
    static status_t validateAudioDescriptionMixLevel(float leveldB);

    /**
     * Return NO_ERROR if dualMonoMode is one of the enum values, otherwise BAD_VALUE.
     */
    static status_t validateDualMonoMode(audio_dual_mono_mode_t dualMonoMode);

    /**
     * Return NO_ERROR if fallbackMode is one of the enum values, otherwise BAD_VALUE.
     */
    static status_t validatePlaybackRateFallbackMode(
            audio_timestretch_fallback_mode_t fallbackMode);

    /**
     * Return NO_ERROR if fallbackMode is one of the enum values, otherwise BAD_VALUE.
     */
    static status_t validatePlaybackRateStretchMode(audio_timestretch_stretch_mode_t stretchMode);

    /**
     * Return NO_ERROR if playbackRate is acceptable - the enums are correct and the
     * rate and speed non-negative, otherwise BAD_VALUE.
     *
     * This is a basic bounds check - the system might have stricter requirements for
     * playbackRate on a particular stream / device.
     */
    static status_t validatePlaybackRate(const audio_playback_rate_t& playbackRate);
};

}; // namespace android

#endif  /*ANDROID_AUDIO_VALIDATOR_H_*/
