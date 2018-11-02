/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include <system/audio.h>
#include <system/audio_policy.h>
#include <binder/Parcel.h>
#include <utils/String8.h>
#include <utils/Vector.h>

namespace android {

enum product_strategy_t : uint32_t;
const product_strategy_t PRODUCT_STRATEGY_NONE = static_cast<product_strategy_t>(-1);

using AttributesVector = std::vector<audio_attributes_t>;

} // namespace android

