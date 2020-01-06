/*
 * Copyright (C) 2019 The Android Open Source Project
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

#ifndef __EXTRACTOR_H__
#define __EXTRACTOR_H__

#include <media/NdkMediaExtractor.h>

#include "BenchmarkCommon.h"
#include "Stats.h"

class Extractor {
  public:
    Extractor()
        : mFormat(nullptr),
          mExtractor(nullptr),
          mStats(nullptr),
          mFrameBuf{nullptr},
          mDurationUs{0} {}

    ~Extractor() {
        if (mStats) delete mStats;
    }

    int32_t initExtractor(int32_t fd, size_t fileSize);

    int32_t setupTrackFormat(int32_t trackId);

    void *getCSDSample(AMediaCodecBufferInfo &frameInfo, int32_t csdIndex);

    int32_t getFrameSample(AMediaCodecBufferInfo &frameInfo);

    int32_t extract(int32_t trackId);

    void dumpStatistics(string inputReference, string componentName = "", string statsFile = "");

    void deInitExtractor();

    AMediaFormat *getFormat() { return mFormat; }

    uint8_t *getFrameBuf() { return mFrameBuf; }

    int64_t getClipDuration() { return mDurationUs; }

  private:
    AMediaFormat *mFormat;
    AMediaExtractor *mExtractor;
    Stats *mStats;
    uint8_t *mFrameBuf;
    int64_t mDurationUs;
};

#endif  // __EXTRACTOR_H__