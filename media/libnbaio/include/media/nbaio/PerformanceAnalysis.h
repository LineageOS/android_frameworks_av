/*
 * Copyright (C) 2017 The Android Open Source Project
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

// Non-blocking event logger intended for safe communication between processes via shared memory

#ifndef ANDROID_MEDIA_PERFORMANCEANALYSIS_H
#define ANDROID_MEDIA_PERFORMANCEANALYSIS_H

#include <map>
#include <deque>
#include <vector>
#include "NBLog.h"

namespace android {

class String8;

class PerformanceAnalysis {
    // This class stores and analyzes audio processing wakeup timestamps from NBLog
    // FIXME: currently, all performance data is stored in deques. Need to add a mutex.
    // FIXME: continue this way until analysis is done in a separate thread. Then, use
    // the fifo writer utilities.
public:

    PerformanceAnalysis();

    // FIXME: decide whether to use 64 or 32 bits
    typedef uint64_t log_hash_t;

    // stores a short-term histogram of size determined by kShortHistSize
    // key: observed buffer period. value: count
    // TODO: unsigned, unsigned
    // TODO: change this name to histogram
    using short_histogram = std::map<int, int>;

    using outlierInterval = uint64_t;
    // int64_t timestamps are converted to uint64_t in PerformanceAnalysis::storeOutlierData,
    // and all further analysis functions use uint64_t.
    using timestamp = uint64_t;
    using timestamp_raw = int64_t;

    // Writes wakeup timestamp entry to log and runs analysis
    // author is the thread ID
    // TODO: check. if the thread has multiple histograms, is author info correct
    // FIXME: remove author from arglist. Want to call these function separately on
    // each thread’s data.
    // FIXME: decide whether to store the hash (source file location) instead
    // FIXME: If thread has multiple histograms, check that code works and correct
    // author is stored (test with multiple threads). Need to check that the current
    // code is not receiving data from multiple threads. This could cause odd values.
    void logTsEntry(int author, timestamp_raw ts);

    // FIXME: make peakdetector and storeOutlierData a single function
    // Input: mOutlierData. Looks at time elapsed between outliers
    // finds significant changes in the distribution
    // writes timestamps of significant changes to mPeakTimestamps
    void detectPeaks();

    // runs analysis on timestamp series before it is converted to a histogram
    // finds outliers
    // writes to mOutlierData <time elapsed since previous outlier, outlier timestamp>
    void storeOutlierData(const std::vector<timestamp_raw> &timestamps);

    // input: series of short histograms. Generates a string of analysis of the buffer periods
    // TODO: WIP write more detailed analysis
    // FIXME: move this data visualization to a separate class. Model/view/controller
    void reportPerformance(String8 *body, int maxHeight = 10);

    // TODO: delete this. temp for testing
    void testFunction();

    // This function used to detect glitches in a time series
    // TODO incorporate this into the analysis (currently unused)
    void     alertIfGlitch(const std::vector<timestamp_raw> &samples);

    ~PerformanceAnalysis() {}

private:

    // stores outlier analysis: <elapsed time between outliers in ms, outlier timestamp>
    std::deque<std::pair<outlierInterval, timestamp>> mOutlierData;

    // stores each timestamp at which a peak was detected
    // a peak is a moment at which the average outlier interval changed significantly
    std::deque<timestamp> mPeakTimestamps;

    // FIFO of small histograms
    // stores fixed-size short buffer period histograms with hash and thread data
    // TODO: Turn it into a circular buffer for better data flow
    std::deque<std::pair<int, short_histogram>> mRecentHists;

    // map from author to vector of timestamps, collected from NBLog
    // when a vector reaches its maximum size, analysis is run and the data is deleted
    std::map<int, std::vector<timestamp_raw>> mTimeStampSeries;

    // TODO: measure these from the data (e.g., mode) as they may change.
    // const int kGlitchThreshMs = 7;
    // const int kMsPerSec = 1000;

    // Parameters used when detecting outliers
    // TODO: learn some of these from the data, delete unused ones
    // FIXME: decide whether to make kPeriodMs static.
    // The non-const values are (TODO: will be) learned from the data
    static const int kNumBuff = 3; // number of buffers considered in local history
    int kPeriodMs; // current period length is ideally 4 ms
    static const int kOutlierMs = 7; // values greater or equal to this cause glitches
    // DAC processing time for 4 ms buffer
    static constexpr double kRatio = 0.75; // estimate of CPU time as ratio of period length
    int kPeriodMsCPU; // compute based on kPeriodLen and kRatio

    // Peak detection: number of standard deviations from mean considered a significant change
    static const int kStddevThreshold = 5;

    static const int kRecentHistsCapacity = 100; // number of short-term histograms stored in memory
    static const int kShortHistSize = 50; // number of samples in a short-term histogram

    // these variables are stored in-class to ensure continuity while analyzing the timestamp
    // series one short sequence at a time: the variables are not re-initialized every time.
    // FIXME: create inner class for these variables and decide which other ones to add to it
    double mPeakDetectorMean = -1;
    double mPeakDetectorSd = -1;
    // variables for storeOutlierData
    uint64_t mElapsed = 0;
    int64_t mPrevNs = -1;

};

static inline int deltaMs(int64_t ns1, int64_t ns2) {
    return (ns2 - ns1) / (1000 * 1000);
}

static inline uint32_t log2(uint32_t x) {
    // This works for x > 0
    return 31 - __builtin_clz(x);
}

}   // namespace android

#endif  // ANDROID_MEDIA_PERFORMANCEANALYSIS_H
