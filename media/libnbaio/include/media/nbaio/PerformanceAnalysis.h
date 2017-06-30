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

namespace android {

class String8;

class PerformanceAnalysis {

public:

PerformanceAnalysis();

// stores a short-term histogram of size determined by kShortHistSize
// TODO: unsigned, unsigned
// CHECK: is there a better way to use short_histogram than to write 'using'
// both in this header file and in NBLog.h?
using short_histogram = std::map<int, int>;

// returns a vector of pairs <outlier timestamp, time elapsed since previous outlier
// called by NBLog::Reader::dump before data is converted into histogram
// TODO: currently, the elapsed time
// The resolution is only as good as the ms duration of one shortHist
void storeOutlierData(int author, const std::vector<int64_t> &timestamps);

// TODO: delete this. temp for testing
void testFunction();

// Given a series, looks for changes in distribution (peaks)
// Returns a 'signal' array of the same length as the series, where each
// value is mapped to -1, 0, or 1 based on whether a negative or positive peak
// was detected, or no significant change occurred.
// The function sets the mean to the starting value and sigma to 0, and updates
// them as long as no peak is detected. When a value is more than 'threshold'
// standard deviations from the mean, a peak is detected and the mean and sigma
// are set to the peak value and 0.
// static void peakDetector();

// input: series of short histograms. output: prints an analysis of the
// data to the console
// TODO: change this so that it writes the analysis to the long-term
// circular buffer and prints an analyses both for the short and long-term
void reportPerformance(String8 *body,
                       const std::deque<std::pair
                       <int, short_histogram>> &shortHists,
                       int maxHeight = 10);

// if findGlitch is true, log warning when buffer periods caused glitch
// TODO adapt this to the analysis in reportPerformance instead of logging
void     alertIfGlitch(const std::vector<int64_t> &samples);
bool     isFindGlitch() const;
void     setFindGlitch(bool s);

~PerformanceAnalysis() {}

private:

// stores outlier analysis
std::vector<std::pair<uint64_t, uint64_t>> mOutlierData;

// stores long-term audio performance data
// TODO: Turn it into a circular buffer
std::deque<std::pair<int, int>> mPerformanceAnalysis;

// alert if a local buffer period sequence caused an audio glitch
bool findGlitch;
//TODO: measure these from the data (e.g., mode) as they may change.
//const int kGlitchThreshMs = 7;
// const int kMsPerSec = 1000;
const int kNumBuff = 3; // number of buffers considered in local history
const int kPeriodMs = 4; // current period length is ideally 4 ms
const int kOutlierMs = 7; // values greater or equal to this cause glitches every time
// DAC processing time for 4 ms buffer
static constexpr double kRatio = 0.75; // estimate of CPU time as ratio of period length
int kPeriodMsCPU; //compute based on kPeriodLen and kRatio

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
