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

//#define LOG_NDEBUG 0
#define LOG_TAG "Stats"

#include <ctime>
#include <iostream>
#include <stdint.h>
#include <fstream>

#include "Stats.h"

/**
 * Dumps the stats of the operation for a given input media.
 *
 * \param operation      describes the operation performed on the input media
 *                       (i.e. extract/mux/decode/encode)
 * \param inputReference input media
 * \param durationUs     is a duration of the input media in microseconds.
 * \param componentName  describes the codecName/muxFormat/mimeType.
 * \param mode           the operating mode: sync/async.
 * \param statsFile      the file where the stats data is to be written.
 */
void Stats::dumpStatistics(string operation, string inputReference, int64_t durationUs,
                           string componentName, string mode, string statsFile) {
    ALOGV("In %s", __func__);
    if (!mOutputTimer.size()) {
        ALOGE("No output produced");
        return;
    }
    nsecs_t totalTimeTakenNs = getTotalTime();
    nsecs_t timeTakenPerSec = (totalTimeTakenNs * 1000000) / durationUs;
    nsecs_t timeToFirstFrameNs = *mOutputTimer.begin() - mStartTimeNs;
    int32_t size = std::accumulate(mFrameSizes.begin(), mFrameSizes.end(), 0);
    // get min and max output intervals.
    nsecs_t intervalNs;
    nsecs_t minTimeTakenNs = INT64_MAX;
    nsecs_t maxTimeTakenNs = 0;
    nsecs_t prevIntervalNs = mStartTimeNs;
    for (int32_t idx = 0; idx < mOutputTimer.size() - 1; idx++) {
        intervalNs = mOutputTimer.at(idx) - prevIntervalNs;
        prevIntervalNs = mOutputTimer.at(idx);
        if (minTimeTakenNs > intervalNs) minTimeTakenNs = intervalNs;
        else if (maxTimeTakenNs < intervalNs) maxTimeTakenNs = intervalNs;
    }

    // Write the stats data to file.
    int64_t dataSize = size;
    int64_t bytesPerSec = ((int64_t)dataSize * 1000000000) / totalTimeTakenNs;
    string rowData = "";
    rowData.append(to_string(systemTime(CLOCK_MONOTONIC)) + ", ");
    rowData.append(inputReference + ", ");
    rowData.append(operation + ", ");
    rowData.append(componentName + ", ");
    rowData.append("NDK, ");
    rowData.append(mode + ", ");
    rowData.append(to_string(mInitTimeNs) + ", ");
    rowData.append(to_string(mDeInitTimeNs) + ", ");
    rowData.append(to_string(minTimeTakenNs) + ", ");
    rowData.append(to_string(maxTimeTakenNs) + ", ");
    rowData.append(to_string(totalTimeTakenNs / mOutputTimer.size()) + ", ");
    rowData.append(to_string(timeTakenPerSec) + ", ");
    rowData.append(to_string(bytesPerSec) + ", ");
    rowData.append(to_string(timeToFirstFrameNs) + ", ");
    rowData.append(to_string(size) + ",");
    rowData.append(to_string(totalTimeTakenNs) + ",\n");

    ofstream out(statsFile, ios::out | ios::app);
    if(out.bad()) {
        ALOGE("Failed to open stats file for writing!");
        return;
    }
    out << rowData;
    out.close();
}
