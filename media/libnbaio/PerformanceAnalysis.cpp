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


#define LOG_TAG "PerformanceAnalysis"
// #define LOG_NDEBUG 0

#include <algorithm>
#include <climits>
#include <deque>
#include <fstream>
#include <iostream>
#include <math.h>
#include <numeric>
#include <vector>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <time.h>
#include <new>
#include <audio_utils/roundup.h>
#include <media/nbaio/NBLog.h>
#include <media/nbaio/PerformanceAnalysis.h>
// #include <utils/CallStack.h> // used to print callstack
#include <utils/Log.h>
#include <utils/String8.h>

#include <queue>
#include <utility>

namespace android {

PerformanceAnalysis::PerformanceAnalysis() {
    // These variables will be (FIXME) learned from the data
    kPeriodMs = 4; // typical buffer period (mode)
    // average number of Ms spent processing buffer
    kPeriodMsCPU = static_cast<int>(kPeriodMs * kRatio);
}

// converts a time series into a map. key: buffer period length. value: count
static std::map<int, int> buildBuckets(const std::vector<int64_t> &samples) {
    // TODO allow buckets of variable resolution
    std::map<int, int> buckets;
    for (size_t i = 1; i < samples.size(); ++i) {
        ++buckets[deltaMs(samples[i - 1], samples[i])];
    }
    return buckets;
}

static int widthOf(int x) {
    int width = 0;
    while (x > 0) {
        ++width;
        x /= 10;
    }
    return width;
}

// Takes a single buffer period timestamp entry with author information and stores it
// in a temporary series of timestamps. Once the series is full, the data is analyzed,
// stored, and emptied.
// TODO: decide whether author or file location information is more important to store
// for now, only stores author (thread)
void PerformanceAnalysis::logTsEntry(int author, int64_t ts) {
    // TODO might want to filter excessively high outliers, which are usually caused
    // by the thread being inactive.
    // Store time series data for each reader in order to bucket it once there
    // is enough data. Then, write to recentHists as a histogram.
    mTimeStampSeries[author].push_back(ts);
    // if length of the time series has reached kShortHistSize samples, do 1) and 2):
    if (mTimeStampSeries[author].size() >= kShortHistSize) {
        // 1) analyze the series to store all outliers and their exact timestamps:
        storeOutlierData(mTimeStampSeries[author]);
        // 2) detect peaks in the outlier series
        detectPeaks();
        // 3) compute its histogram, append this to mRecentHists and erase the time series
        // FIXME: need to store the timestamp of the beginning of each histogram
        // FIXME: Restore LOG_HIST_FLUSH to separate histograms at every end-of-stream event
        // A histogram should not span data between audio off/on timespans
        mRecentHists.emplace_back(author,
                                   buildBuckets(mTimeStampSeries[author]));
        // do not let mRecentHists exceed capacity
        // ALOGD("mRecentHists size: %d", static_cast<int>(mRecentHists.size()));
        if (mRecentHists.size() >= kRecentHistsCapacity) {
            //  ALOGD("popped back mRecentHists");
            mRecentHists.pop_front();
        }
        mTimeStampSeries[author].clear();
    }
}

// Given a series of outlier intervals (mOutlier data),
// looks for changes in distribution (peaks), which can be either positive or negative.
// The function sets the mean to the starting value and sigma to 0, and updates
// them as long as no peak is detected. When a value is more than 'threshold'
// standard deviations from the mean, a peak is detected and the mean and sigma
// are set to the peak value and 0.
void PerformanceAnalysis::detectPeaks() {
    if (mOutlierData.empty()) {
        ALOGD("peak detector called on empty array");
        return;
    }

    // compute mean of the distribution. Used to check whether a value is large
    const double kTypicalDiff = std::accumulate(
        mOutlierData.begin(), mOutlierData.end(), 0,
        [](auto &a, auto &b){return a + b.first;}) / mOutlierData.size();
    // ALOGD("typicalDiff %f", kTypicalDiff);

    // iterator at the beginning of a sequence, or updated to the most recent peak
    std::deque<std::pair<uint64_t, uint64_t>>::iterator start = mOutlierData.begin();
    // the mean and standard deviation are updated every time a peak is detected
    // initialize first time. The mean from the previous sequence is stored
    // for the next sequence. Here, they are initialized for the first time.
    if (mPeakDetectorMean < 0) {
        mPeakDetectorMean = static_cast<double>(start->first);
        mPeakDetectorSd = 0;
    }
    auto sqr = [](auto x){ return x * x; };
    for (auto it = mOutlierData.begin(); it != mOutlierData.end(); ++it) {
        // no surprise occurred:
        // the new element is a small number of standard deviations from the mean
        if ((fabs(it->first - mPeakDetectorMean) < kStddevThreshold * mPeakDetectorSd) ||
             // or: right after peak has been detected, the delta is smaller than average
            (mPeakDetectorSd == 0 && fabs(it->first - mPeakDetectorMean) < kTypicalDiff)) {
            // update the mean and sd:
            // count number of elements (distance between start interator and current)
            const int kN = std::distance(start, it) + 1;
            // usual formulas for mean and sd
            mPeakDetectorMean = std::accumulate(start, it + 1, 0.0,
                                   [](auto &a, auto &b){return a + b.first;}) / kN;
            mPeakDetectorSd = sqrt(std::accumulate(start, it + 1, 0.0,
                      [=](auto &a, auto &b){ return a + sqr(b.first - mPeakDetectorMean);})) /
                      ((kN > 1)? kN - 1 : kN); // kN - 1: mean is correlated with variance
            // ALOGD("value, mean, sd: %f, %f, %f", static_cast<double>(it->first), mean, sd);
        }
        // surprising value: store peak timestamp and reset mean, sd, and start iterator
        else {
            mPeakTimestamps.emplace_back(it->second);
            // TODO: remove pop_front once a circular buffer is in place
            if (mPeakTimestamps.size() >= kShortHistSize) {
                ALOGD("popped back mPeakTimestamps");
                mPeakTimestamps.pop_front();
            }
            mPeakDetectorMean = static_cast<double>(it->first);
            mPeakDetectorSd = 0;
            start = it;
        }
    }
    //for (const auto &it : mPeakTimestamps) {
    //    ALOGE("mPeakTimestamps %f", static_cast<double>(it));
    //}
    return;
}

// Called by LogTsEntry. The input is a vector of timestamps.
// Finds outliers and writes to mOutlierdata.
// Each value in mOutlierdata consists of: <outlier timestamp, time elapsed since previous outlier>.
// e.g. timestamps (ms) 1, 4, 5, 16, 18, 28 will produce pairs (4, 5), (13, 18).
// This function is applied to the time series before it is converted into a histogram.
void PerformanceAnalysis::storeOutlierData(const std::vector<int64_t> &timestamps) {
    if (timestamps.size() < 1) {
        ALOGE("storeOutlierData called on empty vector");
        return;
    }
    // first pass: need to initialize
    if (mElapsed == 0) {
        mPrevNs = timestamps[0];
    }
    for (const auto &ts: timestamps) {
        const uint64_t diffMs = static_cast<uint64_t>(deltaMs(mPrevNs, ts));
        if (diffMs >= static_cast<uint64_t>(kOutlierMs)) {
            mOutlierData.emplace_back(mElapsed, static_cast<uint64_t>(mPrevNs));
            // Remove oldest value if the vector is full
            // TODO: remove pop_front once circular buffer is in place
            // FIXME: change kShortHistSize to some other constant. Make sure it is large
            // enough that data will never be lost before being written to a long-term FIFO
            if (mOutlierData.size() >= kShortHistSize) {
                ALOGD("popped back mOutlierData");
                mOutlierData.pop_front();
            }
            mElapsed = 0;
        }
        mElapsed += diffMs;
        mPrevNs = ts;
    }
}


// FIXME: delete this temporary test code, recycled for various new functions
void PerformanceAnalysis::testFunction() {
    // produces values (4: 5000000), (13: 18000000)
    // ns timestamps of buffer periods
    const std::vector<int64_t>kTempTestData = {1000000, 4000000, 5000000,
                                               16000000, 18000000, 28000000};
    PerformanceAnalysis::storeOutlierData(kTempTestData);
    for (const auto &outlier: mOutlierData) {
        ALOGE("PerformanceAnalysis test %lld: %lld",
              static_cast<long long>(outlier.first), static_cast<long long>(outlier.second));
    }
    detectPeaks();
}

// TODO Make it return a std::string instead of modifying body --> is this still relevant?
// FIXME: as can be seen when printing the values, the outlier timestamps typically occur
// in the first histogram 35 to 38 indices from the end (most often 35).
// TODO consider changing all ints to uint32_t or uint64_t
void PerformanceAnalysis::reportPerformance(String8 *body, int maxHeight) {
    if (mRecentHists.size() < 1) {
        ALOGD("reportPerformance: mRecentHists is empty");
        return;
    }
    ALOGD("reportPerformance: hists size %d", static_cast<int>(mRecentHists.size()));
    // TODO: more elaborate data analysis
    std::map<int, int> buckets;
    for (const auto &shortHist: mRecentHists) {
        for (const auto &countPair : shortHist.second) {
            buckets[countPair.first] += countPair.second;
        }
    }

    // underscores and spaces length corresponds to maximum width of histogram
    static const int kLen = 40;
    std::string underscores(kLen, '_');
    std::string spaces(kLen, ' ');

    auto it = buckets.begin();
    int maxDelta = it->first;
    int maxCount = it->second;
    // Compute maximum values
    while (++it != buckets.end()) {
        if (it->first > maxDelta) {
            maxDelta = it->first;
        }
        if (it->second > maxCount) {
            maxCount = it->second;
        }
    }
    int height = log2(maxCount) + 1; // maxCount > 0, safe to call log2
    const int leftPadding = widthOf(1 << height);
    const int colWidth = std::max(std::max(widthOf(maxDelta) + 1, 3), leftPadding + 2);
    int scalingFactor = 1;
    // scale data if it exceeds maximum height
    if (height > maxHeight) {
        scalingFactor = (height + maxHeight) / maxHeight;
        height /= scalingFactor;
    }
    body->appendFormat("\n%*s", leftPadding + 11, "Occurrences");
    // write histogram label line with bucket values
    body->appendFormat("\n%s", " ");
    body->appendFormat("%*s", leftPadding, " ");
    for (auto const &x : buckets) {
        body->appendFormat("%*d", colWidth, x.second);
    }
    // write histogram ascii art
    body->appendFormat("\n%s", " ");
    for (int row = height * scalingFactor; row >= 0; row -= scalingFactor) {
        const int value = 1 << row;
        body->appendFormat("%.*s", leftPadding, spaces.c_str());
        for (auto const &x : buckets) {
          body->appendFormat("%.*s%s", colWidth - 1, spaces.c_str(), x.second < value ? " " : "|");
        }
        body->appendFormat("\n%s", " ");
    }
    // print x-axis
    const int columns = static_cast<int>(buckets.size());
    body->appendFormat("%*c", leftPadding, ' ');
    body->appendFormat("%.*s", (columns + 1) * colWidth, underscores.c_str());
    body->appendFormat("\n%s", " ");

    // write footer with bucket labels
    body->appendFormat("%*s", leftPadding, " ");
    for (auto const &x : buckets) {
        body->appendFormat("%*d", colWidth, x.first);
    }
    body->appendFormat("%.*s%s", colWidth, spaces.c_str(), "ms\n");

    // Now report glitches
    body->appendFormat("\ntime elapsed between glitches and glitch timestamps\n");
    for (const auto &outlier: mOutlierData) {
        body->appendFormat("%lld: %lld\n", static_cast<long long>(outlier.first),
                           static_cast<long long>(outlier.second));
    }

}


// Produces a log warning if the timing of recent buffer periods caused a glitch
// Computes sum of running window of three buffer periods
// Checks whether the buffer periods leave enough CPU time for the next one
// e.g. if a buffer period is expected to be 4 ms and a buffer requires 3 ms of CPU time,
// here are some glitch cases:
// 4 + 4 + 6 ; 5 + 4 + 5; 2 + 2 + 10
// TODO: develop this code to track changes in histogram distribution in addition
// to / instead of glitches.
void PerformanceAnalysis::alertIfGlitch(const std::vector<int64_t> &samples) {
    std::deque<int> periods(kNumBuff, kPeriodMs);
    for (size_t i = 2; i < samples.size(); ++i) { // skip first time entry
        periods.push_front(deltaMs(samples[i - 1], samples[i]));
        periods.pop_back();
        // TODO: check that all glitch cases are covered
        if (std::accumulate(periods.begin(), periods.end(), 0) > kNumBuff * kPeriodMs +
            kPeriodMs - kPeriodMsCPU) {
                ALOGW("A glitch occurred");
                periods.assign(kNumBuff, kPeriodMs);
        }
    }
    return;
}

}   // namespace android
