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

#include <aidl/android/media/audio/eraser/SoundClassification.h>
#include <map>
#include <vector>

namespace aidl::android::hardware::audio::effect {

using aidl::android::media::audio::eraser::SoundClassification;

// Defines the mapping from YAMNet class indices to our custom SoundClassification categories.
const std::map<SoundClassification, std::vector<int>>& getYamnetToCustomCategoryMap();

}  // namespace aidl::android::hardware::audio::effect
