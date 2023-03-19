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

#pragma once

#include <optional>

#include <aidl/android/hardware/audio/effect/BnEffect.h>

#include <audio_effects/effect_aec.h>
#include <audio_effects/effect_agc.h>
#include <audio_effects/effect_agc2.h>
#include <audio_effects/effect_ns.h>
#include <system/audio_effects/effect_uuid.h>

#include "effect-impl/EffectTypes.h"

namespace aidl::android::hardware::audio::effect {

// Acoustic Echo Cancellation
static const std::string kAcousticEchoCancelerEffectName = "Acoustic Echo Canceler";
static const std::vector<Range::AcousticEchoCancelerRange> kAcousticEchoCancelerRanges = {
        MAKE_RANGE(AcousticEchoCanceler, AcousticEchoCanceler::echoDelayUs, 0, 500)};
static const Capability kAcousticEchoCancelerCap = {.range = kAcousticEchoCancelerRanges};
static const Descriptor kAcousticEchoCancelerDesc = {
        .common = {.id = {.type = getEffectTypeUuidAcousticEchoCanceler(),
                          .uuid = getEffectImplUuidAcousticEchoCancelerSw(),
                          .proxy = std::nullopt},
                   .flags = {.type = Flags::Type::PRE_PROC, .deviceIndication = true},
                   .name = kAcousticEchoCancelerEffectName,
                   .implementor = "The Android Open Source Project"},
        .capability = kAcousticEchoCancelerCap};

// Automatic Gain Control 1
static const std::string kAutomaticGainControlV1EffectName = "Automatic Gain Control V1";
static const std::vector<Range::AutomaticGainControlV1Range> kAutomaticGainControlV1Ranges = {
        MAKE_RANGE(AutomaticGainControlV1, AutomaticGainControlV1::targetPeakLevelDbFs, -3100, 0),
        MAKE_RANGE(AutomaticGainControlV1, AutomaticGainControlV1::maxCompressionGainDb, 0, 9000)};
static const Capability kAutomaticGainControlV1Cap = {.range = kAutomaticGainControlV1Ranges};
static const Descriptor kAutomaticGainControlV1Desc = {
        .common = {.id = {.type = getEffectTypeUuidAutomaticGainControlV1(),
                          .uuid = getEffectImplUuidAutomaticGainControlV1Sw(),
                          .proxy = std::nullopt},
                   .flags = {.type = Flags::Type::PRE_PROC, .deviceIndication = true},
                   .name = kAutomaticGainControlV1EffectName,
                   .implementor = "The Android Open Source Project"},
        .capability = kAutomaticGainControlV1Cap};

// Automatic Gain Control 2
static const std::string kAutomaticGainControlV2EffectName = "Automatic Gain Control V2";
const std::vector<Range::AutomaticGainControlV2Range> kAutomaticGainControlV2Ranges = {
        MAKE_RANGE(AutomaticGainControlV2, AutomaticGainControlV2::fixedDigitalGainMb, 0, 90),
        // extra_staturation_margin_db is no longer configurable in webrtc
        MAKE_RANGE(AutomaticGainControlV2, AutomaticGainControlV2::saturationMarginMb, 2, 2),
        // WebRTC only supports RMS level estimator now
        MAKE_RANGE(AutomaticGainControlV2, AutomaticGainControlV2::levelEstimator,
                   AutomaticGainControlV2::LevelEstimator::RMS,
                   AutomaticGainControlV2::LevelEstimator::RMS)};
static const Capability kAutomaticGainControlV2Cap = {.range = kAutomaticGainControlV2Ranges};
static const Descriptor kAutomaticGainControlV2Desc = {
        .common = {.id = {.type = getEffectTypeUuidAutomaticGainControlV2(),
                          .uuid = getEffectImplUuidAutomaticGainControlV2Sw(),
                          .proxy = std::nullopt},
                   .flags = {.type = Flags::Type::PRE_PROC, .deviceIndication = true},
                   .name = kAutomaticGainControlV2EffectName,
                   .implementor = "The Android Open Source Project"},
        .capability = kAutomaticGainControlV2Cap};

// Noise suppression
static const std::string kNoiseSuppressionEffectName = "Noise Suppression";
static const Descriptor kNoiseSuppressionDesc = {
        .common = {.id = {.type = getEffectTypeUuidNoiseSuppression(),
                          .uuid = getEffectImplUuidNoiseSuppressionSw(),
                          .proxy = std::nullopt},
                   .flags = {.type = Flags::Type::PRE_PROC, .deviceIndication = true},
                   .name = kNoiseSuppressionEffectName,
                   .implementor = "The Android Open Source Project"}};

enum class PreProcessingEffectType {
    ACOUSTIC_ECHO_CANCELLATION,
    AUTOMATIC_GAIN_CONTROL_V1,
    AUTOMATIC_GAIN_CONTROL_V2,
    NOISE_SUPPRESSION,
};

inline std::ostream& operator<<(std::ostream& out, const PreProcessingEffectType& type) {
    switch (type) {
        case PreProcessingEffectType::ACOUSTIC_ECHO_CANCELLATION:
            return out << kAcousticEchoCancelerEffectName;
        case PreProcessingEffectType::AUTOMATIC_GAIN_CONTROL_V1:
            return out << kAutomaticGainControlV1EffectName;
        case PreProcessingEffectType::AUTOMATIC_GAIN_CONTROL_V2:
            return out << kAutomaticGainControlV2EffectName;
        case PreProcessingEffectType::NOISE_SUPPRESSION:
            return out << kNoiseSuppressionEffectName;
    }
    return out << "EnumPreProcessingEffectTypeError";
}

}  // namespace aidl::android::hardware::audio::effect
