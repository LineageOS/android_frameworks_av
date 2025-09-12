/*
 * Copyright (C) 2025 The Android Open Source Project
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

#include "LiteRTInstance.h"

#include <android-base/logging.h>
#include <string>
#include <vector>

namespace aidl::android::hardware::audio::effect {

/**
 * The Separator class designed to process a single-channel audio stream, identify multiple sound
 * sources and separate them into different output channels.
 *
 * It fetch audio samples from the internal buffer,overlapping audio for more robust separation with
 * windows sliding, and executing model inference to produce the separated audio streams.
 */
class Separator final : public LiteRTInstance {
  public:
    /**
     * @brief Constructs a Separator instance.
     *
     * Initializes the separator with the path to a TFLite model file and the number of output
     * channels the model is expected to produce with single channel audio input. The model is
     * loaded and prepared for inference when initialize() is called.
     */
    Separator(const std::string& modelPath, int outputChannels)
        : LiteRTInstance(modelPath), mOutputChannels(outputChannels) {}

    /**
     * @brief Release Separator instance resources by cleanup the TFLite model and interpreter.
     */
    ~Separator() { LOG(DEBUG) << __func__; }

    /**
     * @brief Buffers the input audio and runs inference when a sufficient number of samples have
     * been accumulated (available audio samples is enough to fill the input tensor size).
     */
    bool process(const std::span<float>& input, std::vector<std::vector<float>>& output);

  private:
    const size_t mOutputChannels;
};

}  // namespace aidl::android::hardware::audio::effect
