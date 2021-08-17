/*
 * Copyright 2020 The Android Open Source Project
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

#include <algorithm>
#include <unistd.h>

#ifdef __ANDROID__
#include <audio_utils/primitives.h>
#endif

#include "AudioProcessorBase.h"
#include "SourceI32.h"

using namespace flowgraph;

SourceI32::SourceI32(int32_t channelCount)
        : AudioSource(channelCount) {
}

int32_t SourceI32::onProcess(int64_t framePosition, int32_t numFrames) {
    float *floatData = output.getBlock();
    int32_t channelCount = output.getSamplesPerFrame();

    int32_t framesLeft = mSizeInFrames - mFrameIndex;
    int32_t framesToProcess = std::min(numFrames, framesLeft);
    int32_t numSamples = framesToProcess * channelCount;

    const int32_t *intBase = static_cast<const int32_t *>(mData);
    const int32_t *intData = &intBase[mFrameIndex * channelCount];

#ifdef __ANDROID__
    memcpy_to_float_from_i32(floatData, intData, numSamples);
#else
    for (int i = 0; i < numSamples; i++) {
        *floatData++ = *intData++ * kScale;
    }
#endif

    mFrameIndex += framesToProcess;
    return framesToProcess;
}
