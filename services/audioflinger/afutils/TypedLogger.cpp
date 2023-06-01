/*
 *
 * Copyright 2017, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "AudioFlinger"
//#define LOG_NDEBUG 0
#include <utils/Log.h>

#include <pthread.h>
#include "TypedLogger.h"

namespace android::aflog {

// External linkage access of thread local storage outside of this shared library
// causes orphaned memory allocations.  This occurs in the implementation of
// __emutls_get_address(), see b/284657986.
//
// We only expose a thread local storage getter and setter here, not the
// actual thread local variable.

namespace {
thread_local NBLog::Writer *tlNBLogWriter;
} // namespace

NBLog::Writer *getThreadWriter() {
    return tlNBLogWriter;
}

void setThreadWriter(NBLog::Writer *writer) {
    tlNBLogWriter = writer;
}

} // namespace android::aflog
