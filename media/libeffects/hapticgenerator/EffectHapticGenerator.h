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

#ifndef ANDROID_EFFECTHAPTICGENERATOR_H_
#define ANDROID_EFFECTHAPTICGENERATOR_H_

#include <functional>
#include <vector>
#include <map>

#include <hardware/audio_effect.h>
#include <system/audio_effect.h>
#include <vibrator/ExternalVibrationUtils.h>

#include "Processors.h"

namespace android::audio_effect::haptic_generator {

//-----------------------------------------------------------------------------
// Definition
//-----------------------------------------------------------------------------

enum hapticgenerator_state_t {
    HAPTICGENERATOR_STATE_UNINITIALIZED,
    HAPTICGENERATOR_STATE_INITIALIZED,
    HAPTICGENERATOR_STATE_ACTIVE,
};

// parameters for each haptic generator
struct HapticGeneratorParam {
    uint32_t hapticChannelSource[2]; // The audio channels used to generate haptic channels.
                                     // The first channel will be used to generate HAPTIC_A,
                                     // The second channel will be used to generate HAPTIC_B
                                     // The value will be offset of audio channel
    uint32_t audioChannelCount;
    uint32_t hapticChannelCount;

    // A map from track id to haptic intensity.
    std::map<int, os::HapticLevel> id2Intensity;
    os::HapticLevel maxHapticIntensity; // max intensity will be used to scale haptic data.
    float maxHapticAmplitude; // max amplitude will be used to limit haptic data absolute values.

    float resonantFrequency;
    float bpfQ;
    float slowEnvNormalizationPower;
    float bsfZeroQ;
    float bsfPoleQ;
    float distortionCornerFrequency;
    float distortionInputGain;
    float distortionCubeThreshold;
    float distortionOutputGain;
};

// A structure to keep all shared pointers for all processors in HapticGenerator.
struct HapticGeneratorProcessorsRecord {
    std::vector<std::shared_ptr<HapticBiquadFilter>> filters;
    std::vector<std::shared_ptr<Ramp>> ramps;
    std::vector<std::shared_ptr<SlowEnvelope>> slowEnvs;
    std::vector<std::shared_ptr<Distortion>> distortions;

    // Cache band-pass filter and band-stop filter for updating parameters
    // according to vibrator info
    std::shared_ptr<HapticBiquadFilter> bpf;
    std::shared_ptr<HapticBiquadFilter> bsf;
};

// A structure to keep all the context for HapticGenerator.
struct HapticGeneratorContext {
    const struct effect_interface_s *itfe;
    effect_config_t config;
    hapticgenerator_state_t state;
    struct HapticGeneratorParam param;
    size_t audioDataBytesPerFrame;

    // A cache for all shared pointers of the HapticGenerator
    struct HapticGeneratorProcessorsRecord processorsRecord;

    // Using a vector of functions to record the processing chain for haptic-generating algorithm.
    // The three parameters of the processing functions are pointer to output buffer, pointer to
    // input buffer and frame count.
    std::vector<std::function<void(float*, const float*, size_t)>> processingChain;

    // inputBuffer is where to keep input buffer for the generating algorithm. It will be
    // constructed according to HapticGeneratorParam.hapticChannelSource.
    std::vector<float> inputBuffer;

    // outputBuffer is a buffer having the same length as inputBuffer. It can be used as
    // intermediate buffer in the generating algorithm.
    std::vector<float> outputBuffer;
};

//-----------------------------------------------------------------------------
// Effect API
//-----------------------------------------------------------------------------

int32_t HapticGeneratorLib_Create(const effect_uuid_t *uuid,
                                  int32_t sessionId,
                                  int32_t ioId,
                                  effect_handle_t *handle);

int32_t HapticGeneratorLib_Release(effect_handle_t handle);

int32_t HapticGeneratorLib_GetDescriptor(const effect_uuid_t *uuid,
                                         effect_descriptor_t *descriptor);

int32_t HapticGenerator_Process(effect_handle_t self,
                                audio_buffer_t *inBuffer,
                                audio_buffer_t *outBuffer);

int32_t HapticGenerator_Command(effect_handle_t self,
                                uint32_t cmdCode,
                                uint32_t cmdSize,
                                void *cmdData,
                                uint32_t *replySize,
                                void *replyData);

int32_t HapticGenerator_GetDescriptor(effect_handle_t self,
                                      effect_descriptor_t *descriptor);

} // namespace android::audio_effect::haptic_generator

#endif // ANDROID_EFFECTHAPTICGENERATOR_H_
