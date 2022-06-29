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

#include <string>
#include <unistd.h>

// This should not be directly included by clients.
// Use MediaUtilsDelayed.h instead.

namespace android::mediautils::delayed_library {

// Use a dispatch table to return methods from the delayed library
struct DelayedDispatchTable {
    std::string (*getCallStackStringForTid)(pid_t tid);
};

// Match with Android.bp and MediaUtilsDelayed.cpp.
#define MEDIAUTILS_DELAYED_LIBRARY_NAME "libmediautils_delayed.so"

// Match with MediaUtilsDelayed.cpp and MediaUtilsDelayedLibrary.cpp
#define MEDIAUTILS_DELAYED_DISPATCH_TABLE_SYMBOL_NAME "gDelayedDispatchTable"

} // namespace android::mediautils::delayed_library
