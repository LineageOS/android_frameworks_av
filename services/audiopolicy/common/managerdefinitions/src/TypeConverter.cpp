/*
 * Copyright (C) 2015 The Android Open Source Project
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

#include "TypeConverter.h"

namespace android {

#define MAKE_STRING_FROM_ENUM(string) { #string, string }
#define TERMINATOR { .literal = nullptr }

template <>
const DeviceCategoryConverter::Table DeviceCategoryConverter::mTable[] = {
    MAKE_STRING_FROM_ENUM(DEVICE_CATEGORY_HEADSET),
    MAKE_STRING_FROM_ENUM(DEVICE_CATEGORY_SPEAKER),
    MAKE_STRING_FROM_ENUM(DEVICE_CATEGORY_EARPIECE),
    MAKE_STRING_FROM_ENUM(DEVICE_CATEGORY_EXT_MEDIA),
    TERMINATOR
};

template class TypeConverter<DeviceCategoryTraits>;

}; // namespace android
