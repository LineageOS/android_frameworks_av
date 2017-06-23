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
// #include <inttypes.h>
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
	ALOGE("this value should be 4: %d", kPeriodMs);
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

// WIP: uploading this half-written function to get code review on
// cleanup and new file creation.
/*
static std::vector<std::pair<int, int>> outlierIntervals(
        const std::deque<std::pair<int, short_histogram>> &shortHists) {
    // TODO: need the timestamps
    if (shortHists.size() < 1) {
        return;
    }
    // count number of outliers in histogram
    // TODO: need the alertIfGlitch analysis on the time series in NBLog::reader
    // to find all the glitches
    const std::vector<int> glitchCount = std::vector<int>(shortHists.size());
    // Total ms elapsed in each shortHist
    const std::vector<int> timeElapsedMs = std::vector<int>(shortHists.size());
    int i = 0;
    for (const auto &shortHist: shortHists) {
        for (const auto &bin: shortHist) {
            timeElapsedMs.at(i) += bin->first * bin->second;
            if (bin->first >= kGlitchThreshMs) {
                glitchCount.at(i) += bin->second;
            }
        }
        i++;
    }
    // seconds between glitches and corresponding timestamp
    const std::vector<std::pair<double, int>> glitchFreeIntervalsSec;
    // Sec since last glitch. nonzero if the duration spans many shortHists
    double glitchFreeSec = 0;
    for (int i = 0; i < kGlitchCount.size(); i++) {
      if (kGlitchCount.at(i) == 0) {
        glitchFreeSec += static_cast<double>timeElapsedMs.at(i) / kMsPerSec;
      }
      else {
        // average time between glitches in this interval
        const double kInterval = static_cast<double>(timeElapsedMs.at(i)) / kGlitchCount.at(i);
        for (int j = 0; j < kGlitchCount.at(i); j++) {
          kIntervals.emplace_front(kInterval);
        }
      }
    }
    return;
}*/

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
//TODO: ask Andy where to keep '= 4'
const int PerformanceAnalysis::kPeriodMs; //  = 4;

}   // namespace android
