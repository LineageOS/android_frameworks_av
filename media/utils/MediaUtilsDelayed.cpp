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

#include <mediautils/Library.h>
#include <mediautils/MediaUtilsDelayed.h>
#include "MediaUtilsDelayedLibrary.h"

#define LOG_TAG "MediaUtilsDelayed"
#include <utils/Log.h>
#include <memory>

namespace android::mediautils {

namespace {
//  Specific implementation details for MediaUtils Delayed Library.

// The following use static Meyer's singleton caches instead of letting
// refcounted management as provided above. This is for speed.
std::shared_ptr<void> getDelayedLibrary() {
    static std::shared_ptr<void> library = loadLibrary(MEDIAUTILS_DELAYED_LIBRARY_NAME);
    return library;
}

// Get the delayed dispatch table.  This is refcounted and keeps the underlying library alive.
std::shared_ptr<delayed_library::DelayedDispatchTable> getDelayedDispatchTable() {
    static auto delayedDispatchTable =
            getObjectFromLibrary<delayed_library::DelayedDispatchTable>(
                    MEDIAUTILS_DELAYED_DISPATCH_TABLE_SYMBOL_NAME, getDelayedLibrary());
    return delayedDispatchTable;
}

} // namespace

// Public implementations of methods here.

std::string getCallStackStringForTid(pid_t tid) {
    auto delayedDispatchTable = getDelayedDispatchTable();
    if (!delayedDispatchTable) return {};  // on failure, return empty string
    return delayedDispatchTable->getCallStackStringForTid(tid);
}

} // android::mediautils
