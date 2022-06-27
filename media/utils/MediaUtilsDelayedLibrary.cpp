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

#include "MediaUtilsDelayedLibrary.h"
#include <utils/CallStack.h>

// Methods that are dynamically linked.
namespace {

std::string getCallStackStringForTid(pid_t tid) {
    android::CallStack cs{};
    cs.update(0 /* ignoreDepth */, tid);
    return cs.toString().c_str();
}

} // namespace

// leave global, this is picked up from dynamic linking
android::mediautils::delayed_library::DelayedDispatchTable gDelayedDispatchTable {
    getCallStackStringForTid,
};
