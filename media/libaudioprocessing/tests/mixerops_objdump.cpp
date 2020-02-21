/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include <inttypes.h>
#include <type_traits>
#include "../../../../system/media/audio_utils/include/audio_utils/primitives.h"
#define LOG_ALWAYS_FATAL(...)

#include <../AudioMixerOps.h>

using namespace android;

template <int MIXTYPE, int NCHAN>
static void checkVolumeRampMulti() {
    constexpr size_t FRAME_COUNT = 1000;
    constexpr size_t SAMPLE_COUNT = FRAME_COUNT * NCHAN;

    // data inialized to 0.
    float out[SAMPLE_COUNT]{};
    float in[SAMPLE_COUNT]{};
    float aux[FRAME_COUNT]{};

    // volume initialized to 0
    float vola = 0.f;
    float vol[2] = {0.f, 0.f};

    // some volume increment
    float volainc = 0.01f;
    float volinc[2] = {0.01f, 0.01f};

    // try the multi ramp code.
    volumeRampMulti<MIXTYPE, NCHAN>(out, FRAME_COUNT, in, aux, vol, volinc, &vola, volainc);
}

// Use this to check the objdump to ensure reasonable code.
int main() {
    checkVolumeRampMulti<MIXTYPE_MULTI_STEREOVOL, 5>();
    return EXIT_SUCCESS;
}
