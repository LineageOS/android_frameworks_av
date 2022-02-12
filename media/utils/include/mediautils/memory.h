/*
 * Copyright (C) 2022 The Android Open Source Project
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

namespace android {

namespace {
struct FreeDeleter {
    void operator()(void* p) { free(p); }
};

}  // namespace

/**
 * Used to wrap pointers allocated by legacy code using malloc / calloc / etc.
 */
template <typename T>
using unique_malloced_ptr = std::unique_ptr<T, FreeDeleter>;

}  // namespace android
