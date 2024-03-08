/*
 * Copyright (C) 2014 The Android Open Source Project
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

#include <stdint.h>
#include <type_traits>
#include "Configuration.h"
#include "FastThreadDumpState.h"

namespace android {

struct FastCaptureDumpState : FastThreadDumpState {
    void dump(int fd) const;    // should only be called on a stable copy, not the original

    // FIXME by renaming, could pull up many of these to FastThreadDumpState
    uint32_t mReadSequence = 0;  // incremented before and after each read()
    uint32_t mFramesRead = 0;    // total number of frames read successfully
    uint32_t mReadErrors = 0;    // total number of read() errors
    uint32_t mSampleRate = 0;
    size_t   mFrameCount = 0;
    bool     mSilenced = false; // capture is silenced
};

// No virtuals
static_assert(!std::is_polymorphic_v<FastCaptureDumpState>);

}  // namespace android
