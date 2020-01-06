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

#ifndef __MUXER_H__
#define __MUXER_H__

#include <media/NdkMediaMuxer.h>

#include "BenchmarkCommon.h"
#include "Stats.h"
#include "Extractor.h"

typedef enum {
    MUXER_OUTPUT_FORMAT_MPEG_4 = 0,
    MUXER_OUTPUT_FORMAT_WEBM = 1,
    MUXER_OUTPUT_FORMAT_3GPP = 2,
    MUXER_OUTPUT_FORMAT_OGG = 4,
    MUXER_OUTPUT_FORMAT_INVALID = 5,
} MUXER_OUTPUT_T;

class Muxer {
  public:
    Muxer() : mFormat(nullptr), mMuxer(nullptr), mStats(nullptr) { mExtractor = new Extractor(); }

    virtual ~Muxer() {
        if (mStats) delete mStats;
        if (mExtractor) delete mExtractor;
    }

    Stats *getStats() { return mStats; }
    Extractor *getExtractor() { return mExtractor; }

    /* Muxer related utilities */
    int32_t initMuxer(int32_t fd, MUXER_OUTPUT_T outputFormat);
    void deInitMuxer();
    void resetMuxer();

    /* Process the frames and give Muxed output */
    int32_t mux(uint8_t *inputBuffer, vector<AMediaCodecBufferInfo> &frameSizes);

    void dumpStatistics(string inputReference, string codecName = "", string statsFile = "");

  private:
    AMediaFormat *mFormat;
    AMediaMuxer *mMuxer;
    Extractor *mExtractor;
    Stats *mStats;
};

#endif  // __MUXER_H__
