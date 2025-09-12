/*
 * Copyright (C) 2025 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law of agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "Remixer.h"

#include <android-base/logging.h>

namespace aidl::android::hardware::audio::effect {

bool Remixer::process(
        const std::vector<std::pair<std::vector<float /*audioSamples*/>, float /*gainFactor*/>>&
                inputs,
        std::span<float>& output) {
    // Ensure the output buffer is clean if there is no input data.
    if (inputs.empty()) {
        std::fill(output.begin(), output.end(), 0.0f);
    }

    bool first = true;
    const size_t frameCount = output.size();
    // Accumulate the scaled samples from each input channel.
    for (const auto& [inSamples, gainFactor] : inputs) {
        // Ensure channel sizes match the output buffer size.
        if (inSamples.size() != frameCount) {
            LOG(ERROR) << __func__
                       << " Skipping processing with mismatch frame count, output: " << frameCount
                       << ", input: " << inSamples.size();
            return false;
        }

        if (first) {
            for (size_t i = 0; i < frameCount; ++i) output[i] = inSamples[i] * gainFactor;
            first = false;
        } else {
            for (size_t i = 0; i < frameCount; ++i) output[i] += inSamples[i] * gainFactor;
        }
    }

    return true;
}

}  // namespace aidl::android::hardware::audio::effect
