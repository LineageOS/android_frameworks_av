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

#include <cstdint>
#define LOG_TAG "sharedtest"
#include <utils/Log.h>

// Test library which is dynamicly loaded by library_tests.

// Static variable construction.
// Calls A constructor on library load, A destructor on library unload.

int32_t *gPtr = nullptr;  // this pointer is filled with the location to set memory
                          // when ~A() is called.
                          // we cannot use anything internal to this file as the
                          // data segment may no longer exist after unloading the library.
struct A {
    A() {
        ALOGD("%s: gPtr:%p", __func__, gPtr);
    }

    ~A() {
        ALOGD("%s: gPtr:%p", __func__, gPtr);
        if (gPtr != nullptr) {
            *gPtr = 1;
        }
    }
} gA;

//  __attribute__((constructor)) methods occur before any static variable construction.
// Libraries that use __attribute__((constructor)) should not rely on global constructors
// before method call because they will not be initialized before use.
// See heapprofd_client_api.
// NOTE: is this right? Shouldn't it occur after construction?
 __attribute__((constructor))
void onConstruction() {
    ALOGD("%s: in progress", __func__);  // for logcat analysis
}

// __attribute__((destructor)) methods occur before any static variable destruction.
 __attribute__((destructor))
void onDestruction() {
    ALOGD("%s: in progress", __func__);  // for logcat analysis
}
