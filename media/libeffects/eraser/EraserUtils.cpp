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

#include "EraserUtils.h"

#include <ranges>
#include <vector>

namespace aidl::android::hardware::audio::effect {

namespace {

// Helper to generate a sequence of integers.
std::vector<int> iota_vector(std::vector<std::pair<int /*begin*/, int /*end*/>> indexPairs) {
    std::vector<int> result;
    for (const auto& [begin, end] : indexPairs) {
        auto r = std::views::iota(begin, end + 1);
        result.insert(result.end(), r.begin(), r.end());
    }
    return result;
}
}  // namespace

const std::map<SoundClassification, std::vector<int>>&
getYamnetToCustomCategoryMap() {
    [[clang::no_destroy]] static const std::map<SoundClassification, std::vector<int>>
            kYamnetToCustomMap = {
            // HUMAN: [0, 66]
            {SoundClassification::HUMAN, iota_vector({{0, 66}})},
            // ANIMAL: [67, 131]
            {SoundClassification::ANIMAL, iota_vector({{67, 131}})},
            // MUSIC: [132, 276]
            {SoundClassification::MUSIC, iota_vector({{132, 276}})},
            // NATURE: [277, 278], [280, 293]
            {SoundClassification::NATURE, iota_vector({{277, 278}, {280, 293}})},
            // THINGS: [294, 320], [322, 493], [516, 519]
            {SoundClassification::THINGS, iota_vector({{294, 320}, {322, 493}, {516, 519}})},
            // AMBIGUOUS: [494, 499], [509, 515]
            {SoundClassification::AMBIGUOUS, iota_vector({{494, 499}, {509, 515}})},
            // ENVIRONMENT: 279, 321, [500, 508], 520
            {SoundClassification::ENVIRONMENT,
             iota_vector({{279, 279}, {321, 321}, {500, 508}, {520, 520}})},
    };

    return kYamnetToCustomMap;
}

}  // namespace aidl::android::hardware::audio::effect
