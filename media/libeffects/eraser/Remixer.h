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

#include <span>
#include <utility>
#include <vector>

namespace aidl::android::hardware::audio::effect {

/**
 * A stateless remixer for multiple audio channels remixing with gain factor.
 */
class Remixer {
  public:
    /**
     * @brief Mixes and accumulate multiple audio channels into a single output buffer, applying a
     * specific gain to each channel. It assumes all input channels have the same length.
     *
     * @param inputs A vector of pairs, where each pair contains a vector of float samples for an
     *               input channel and a linear gain factor to apply to that channel.
     * @param output A span representing the output buffer where the mixed result is written. The
     *               buffer is cleared before mixing.
     */
    static bool process(const std::vector<std::pair<std::vector<float>, float>>& inputs,
                        std::span<float>& output);
};

}  // namespace aidl::android::hardware::audio::effect
