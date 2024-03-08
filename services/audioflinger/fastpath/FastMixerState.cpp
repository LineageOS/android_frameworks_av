/*
 * Copyright (C) 2012 The Android Open Source Project
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

#define LOG_TAG "FastMixerState"
//#define LOG_NDEBUG 0

#include <cutils/properties.h>
#include "FastMixerState.h"

namespace android {

FastMixerState::FastMixerState() : FastThreadState()
{
    const int ok = pthread_once(&sMaxFastTracksOnce, sMaxFastTracksInit);
    if (ok != 0) {
        ALOGE("%s pthread_once failed: %d", __func__, ok);
    }
}

// static
unsigned FastMixerState::sMaxFastTracks = kDefaultFastTracks;

// static
pthread_once_t FastMixerState::sMaxFastTracksOnce = PTHREAD_ONCE_INIT;

// static
const char *FastMixerState::commandToString(Command command)
{
    const char *str = FastThreadState::commandToString(command);
    if (str != nullptr) {
        return str;
    }
    switch (command) {
    case FastMixerState::MIX:       return "MIX";
    case FastMixerState::WRITE:     return "WRITE";
    case FastMixerState::MIX_WRITE: return "MIX_WRITE";
    }
    LOG_ALWAYS_FATAL("%s", __func__);
}

// static
void FastMixerState::sMaxFastTracksInit()
{
    char value[PROPERTY_VALUE_MAX];
    if (property_get("ro.audio.max_fast_tracks", value, nullptr /* default_value */) > 0) {
        char *endptr;
        const auto ul = strtoul(value, &endptr, 0);
        if (*endptr == '\0' && kMinFastTracks <= ul && ul <= kMaxFastTracks) {
            sMaxFastTracks = (unsigned) ul;
        }
    }
    ALOGI("sMaxFastTracks = %u", sMaxFastTracks);
}

}   // namespace android
