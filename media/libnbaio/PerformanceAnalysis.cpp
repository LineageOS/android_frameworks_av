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

PerformanceAnalysis::PerformanceAnalysis() : findGlitch(false) {
    kPeriodMsCPU = static_cast<int>(PerformanceAnalysis::kPeriodMs * kRatio);
}

static int widthOf(int x) {
    int width = 0;
    while (x > 0) {
        ++width;
        x /= 10;
    }
    return width;
}

// FIXME: delete this temporary test code, recycled for various new functions
void PerformanceAnalysis::testFunction() {
    // produces values (4: 5000000), (13: 18000000)
    // ns timestamps of buffer periods
    const std::vector<int64_t>kTempTestData = {1000000, 4000000, 5000000,
                                               16000000, 18000000, 28000000};
    const int kTestAuthor = 1;
    PerformanceAnalysis::storeOutlierData(kTestAuthor, kTempTestData);
    for (const auto &outlier: mOutlierData) {
        ALOGE("PerformanceAnalysis test %lld: %lld",
              static_cast<long long>(outlier.first), static_cast<long long>(outlier.second));
    }
}

// Each pair consists of: <outlier timestamp, time elapsed since previous outlier>.
// The timestamp of the beginning of the outlier is recorded.
// The elapsed time is from the timestamp of the previous outlier
// e.g. timestamps (ms) 1, 4, 5, 16, 18, 28 will produce pairs (4, 5), (13, 18).
// This function is applied to the time series before it is converted into a histogram.
void PerformanceAnalysis::storeOutlierData(
    int author, const std::vector<int64_t> &timestamps) {
    if (timestamps.size() < 1) {
        ALOGE("storeOutlierData called on empty vector");
        return;
    }
    author++; // temp to avoid unused error until this value is
    // either TODO: used or discarded from the arglist
    author--;
    uint64_t elapsed = 0;
    int64_t prev = timestamps.at(0);
    for (const auto &ts: timestamps) {
        const uint64_t diff = static_cast<uint64_t>(deltaMs(prev, ts));
        if (diff >= static_cast<uint64_t>(kOutlierMs)) {
            mOutlierData.emplace_back(elapsed, static_cast<uint64_t>(prev));
            elapsed = 0;
        }
        elapsed += diff;
        prev = ts;
    }
    // ALOGE("storeOutlierData: result length %zu", outlierData.size());
    // for (const auto &outlier: OutlierData) {
    //    ALOGE("PerformanceAnalysis test %lld: %lld",
    //          static_cast<long long>(outlier.first), static_cast<long long>(outlier.second));
    //}
}

// TODO: implement peak detector
/*
  static void peakDetector() {
  return;
  } */

// TODO put this function in separate file. Make it return a std::string instead of modifying body
// TODO create a subclass of Reader for this and related work
// FIXME: as can be seen when printing the values, the outlier timestamps typically occur
// in the first histogram 35 to 38 indices from the end (most often 35).
// TODO: build histogram buckets earlier and discard timestamps to save memory
// TODO consider changing all ints to uint32_t or uint64_t
void PerformanceAnalysis::reportPerformance(String8 *body,
                                            const std::deque<std::pair
                                            <int, short_histogram>> &shortHists,
                                            int maxHeight) {
    if (shortHists.size() < 1) {
        return;
    }
    // this is temporary code, which only prints out one histogram
    // of all data stored in buffer. The data is not erased, only overwritten.
    // TODO: more elaborate data analysis
    std::map<int, int> buckets;
    for (const auto &shortHist: shortHists) {
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

bool PerformanceAnalysis::isFindGlitch() const
{
    return findGlitch;
}

void PerformanceAnalysis::setFindGlitch(bool s)
{
    findGlitch = s;
}

}   // namespace android
