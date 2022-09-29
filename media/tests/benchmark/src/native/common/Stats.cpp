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
void Stats::dumpStatistics(const string& operation, const string& inputReference,
                           int64_t durationUs, const string& componentName,
                           const string& mode, const string& statsFile) {
    ALOGV("In %s", __func__);
    if (!mOutputTimer.size()) {
        ALOGE("No output produced");
        return;
    }
    if (statsFile.empty()) {
        return uploadMetrics(operation, inputReference, durationUs, componentName,
                              mode);
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

/**
 * Dumps the stats of the operation for a given input media to a listener.
 *
 * \param operation      describes the operation performed on the input media
 *                       (i.e. extract/mux/decode/encode)
 * \param inputReference input media
 * \param durationUs     is a duration of the input media in microseconds.
 * \param componentName  describes the codecName/muxFormat/mimeType.
 * \param mode           the operating mode: sync/async.
 *
 */

#define LOG_METRIC(...) \
    __android_log_print(ANDROID_LOG_INFO, "ForTimingCollector", __VA_ARGS__)

void Stats::uploadMetrics(const string& operation, const string& inputReference,
                          const int64_t& durationUs, const string& componentName,
                          const string& mode) {

    ALOGV("In %s", __func__);
    (void)durationUs;
    (void)componentName;
    if (!mOutputTimer.size()) {
        ALOGE("No output produced");
        return;
    }
    nsecs_t totalTimeTakenNs = getTotalTime();
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
    (void)mode;
    (void)operation;
    (void)inputReference;
    string prefix = "CodecStats_NativeDec";
    prefix.append("_").append(componentName);
    // Reports the time taken to initialize the codec.
    LOG_METRIC("%s_CodecInitTimeNs:%lld", prefix.c_str(), (long long)mInitTimeNs);
    // Reports the time taken to free the codec.
    LOG_METRIC("%s_CodecDeInitTimeNs:%lld", prefix.c_str(), (long long)mDeInitTimeNs);
    // Reports the min time taken between output frames from the codec
    LOG_METRIC("%s_CodecMinTimeNs:%lld", prefix.c_str(), (long long)minTimeTakenNs);
    // Reports the max time between the output frames from the codec
    LOG_METRIC("%s_CodecMaxTimeNs:%lld", prefix.c_str(), (long long)maxTimeTakenNs);
    // Report raw throughout ( bytes/sec ) of the codec for the entire media
    LOG_METRIC("%s_ProcessedBytesPerSec:%lld", prefix.c_str(), (long long)bytesPerSec);
    // Reports the time taken to get the first frame from the codec
    LOG_METRIC("%s_TimeforFirstFrame:%lld", prefix.c_str(), (long long)timeToFirstFrameNs);

}
