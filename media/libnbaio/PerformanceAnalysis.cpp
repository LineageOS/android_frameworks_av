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
#include <media/nbaio/ReportPerformance.h>
#include <utils/Log.h>
#include <utils/String8.h>

#include <queue>
#include <utility>

namespace android {

namespace ReportPerformance {

PerformanceAnalysis::PerformanceAnalysis() {
    // These variables will be (FIXME) learned from the data
    kPeriodMs = 4; // typical buffer period (mode)
    // average number of Ms spent processing buffer
    kPeriodMsCPU = static_cast<int>(kPeriodMs * kRatio);
}

static int widthOf(int x) {
    int width = 0;
    while (x > 0) {
        ++width;
        x /= 10;
    }
    return width;
}


// Given a the most recent timestamp of a series of audio processing
// wakeup timestamps,
// buckets the time interval into a histogram, searches for
// outliers, analyzes the outlier series for unexpectedly
// small or large values and stores these as peaks
void PerformanceAnalysis::logTsEntry(int64_t ts) {
    // after a state change, start a new series and do not
    // record time intervals in-between
    if (mOutlierDistribution.mPrevTs == 0) {
        mOutlierDistribution.mPrevTs = ts;
        return;
    }

    // Check whether the time interval between the current timestamp
    // and the previous one is long enough to count as an outlier
    const bool isOutlier = detectAndStoreOutlier(ts);
    // If an outlier was found, check whether it was a peak
    if (isOutlier) {
        /*bool isPeak =*/ detectAndStorePeak(
            mOutlierData[0].first, mOutlierData[0].second);
        // TODO: decide whether to insert a new empty histogram if a peak
        // TODO: remove isPeak if unused to avoid "unused variable" error
        // occurred at the current timestamp
    }

    // Insert a histogram to mHists if it is empty, or
    // close the current histogram and insert a new empty one if
    // if the current histogram has spanned its maximum time interval.
    if (mHists.empty() ||
        deltaMs(mHists[0].first, ts) >= kMaxLength.HistTimespanMs) {
        mHists.emplace_front(static_cast<uint64_t>(ts), std::map<int, int>());
        // When memory is full, delete oldest histogram
        // TODO: use a circular buffer
        if (mHists.size() >= kMaxLength.Hists) {
            mHists.resize(kMaxLength.Hists);
        }
    }
    // add current time intervals to histogram
    ++mHists[0].second[deltaMs(mOutlierDistribution.mPrevTs, ts)];
    // update previous timestamp
    mOutlierDistribution.mPrevTs = ts;
}


// forces short-term histogram storage to avoid adding idle audio time interval
// to buffer period data
void PerformanceAnalysis::handleStateChange() {
    mOutlierDistribution.mPrevTs = 0;
    return;
}


// Checks whether the time interval between two outliers is far enough from
// a typical delta to be considered a peak.
// looks for changes in distribution (peaks), which can be either positive or negative.
// The function sets the mean to the starting value and sigma to 0, and updates
// them as long as no peak is detected. When a value is more than 'threshold'
// standard deviations from the mean, a peak is detected and the mean and sigma
// are set to the peak value and 0.
bool PerformanceAnalysis::detectAndStorePeak(outlierInterval diff, timestamp ts) {
    bool isPeak = false;
    if (mOutlierData.empty()) {
        return false;
    }
    // Update mean of the distribution
    // TypicalDiff is used to check whether a value is unusually large
    // when we cannot use standard deviations from the mean because the sd is set to 0.
    mOutlierDistribution.mTypicalDiff = (mOutlierDistribution.mTypicalDiff *
            (mOutlierData.size() - 1) + diff) / mOutlierData.size();

    // Initialize short-term mean at start of program
    if (mOutlierDistribution.mMean == 0) {
        mOutlierDistribution.mMean = static_cast<double>(diff);
    }
    // Update length of current sequence of outliers
    mOutlierDistribution.mN++;

    // If statement checks whether a large deviation from the mean occurred.
    // If the standard deviation has been reset to zero, the comparison is
    // instead to the mean of the full mOutlierInterval sequence.
    if ((fabs(static_cast<double>(diff) - mOutlierDistribution.mMean) <
            mOutlierDistribution.kMaxDeviation * mOutlierDistribution.mSd) ||
            (mOutlierDistribution.mSd == 0 &&
            fabs(diff - mOutlierDistribution.mMean) <
            mOutlierDistribution.mTypicalDiff)) {
        // update the mean and sd using online algorithm
        // https://en.wikipedia.org/wiki/
        // Algorithms_for_calculating_variance#Online_algorithm
        mOutlierDistribution.mN++;
        const double kDelta = diff - mOutlierDistribution.mMean;
        mOutlierDistribution.mMean += kDelta / mOutlierDistribution.mN;
        const double kDelta2 = diff - mOutlierDistribution.mMean;
        mOutlierDistribution.mM2 += kDelta * kDelta2;
        mOutlierDistribution.mSd = (mOutlierDistribution.mN < 2) ? 0 :
                sqrt(mOutlierDistribution.mM2 / (mOutlierDistribution.mN - 1));
    } else {
        // new value is far from the mean:
        // store peak timestamp and reset mean, sd, and short-term sequence
        isPeak = true;
        mPeakTimestamps.emplace_front(ts);
        // if mPeaks has reached capacity, delete oldest data
        // Note: this means that mOutlierDistribution values do not exactly
        // match the data we have in mPeakTimestamps, but this is not an issue
        // in practice for estimating future peaks.
        // TODO: turn this into a circular buffer
        if (mPeakTimestamps.size() >= kMaxLength.Peaks) {
            mPeakTimestamps.resize(kMaxLength.Peaks);
        }
        mOutlierDistribution.mMean = 0;
        mOutlierDistribution.mSd = 0;
        mOutlierDistribution.mN = 0;
        mOutlierDistribution.mM2 = 0;
    }
    ALOGD("outlier distr %f %f", mOutlierDistribution.mMean, mOutlierDistribution.mSd);
    return isPeak;
}


// Determines whether the difference between a timestamp and the previous
// one is beyond a threshold. If yes, stores the timestamp as an outlier
// and writes to mOutlierdata in the following format:
// Time elapsed since previous outlier: Timestamp of start of outlier
// e.g. timestamps (ms) 1, 4, 5, 16, 18, 28 will produce pairs (4, 5), (13, 18).
bool PerformanceAnalysis::detectAndStoreOutlier(const int64_t ts) {
    bool isOutlier = false;
    const int64_t diffMs = static_cast<int64_t>(deltaMs(mOutlierDistribution.mPrevTs, ts));
    if (diffMs >= static_cast<int64_t>(kOutlierMs)) {
        isOutlier = true;
        mOutlierData.emplace_front(mOutlierDistribution.mElapsed,
                                  static_cast<uint64_t>(mOutlierDistribution.mPrevTs));
        // Remove oldest value if the vector is full
        // TODO: turn this into a circular buffer
        // TODO: make sure kShortHistSize is large enough that that data will never be lost
        // before being written to file or to a FIFO
        if (mOutlierData.size() >= kMaxLength.Outliers) {
            mOutlierData.resize(kMaxLength.Outliers);
        }
        mOutlierDistribution.mElapsed = 0;
    }
    mOutlierDistribution.mElapsed += diffMs;
    return isOutlier;
}


// TODO Make it return a std::string instead of modifying body --> is this still relevant?
// TODO consider changing all ints to uint32_t or uint64_t
// TODO: move this to ReportPerformance, probably make it a friend function of PerformanceAnalysis
void PerformanceAnalysis::reportPerformance(String8 *body, int maxHeight) {
    if (mHists.empty()) {
        ALOGD("reportPerformance: mHists is empty");
        return;
    }

    std::map<int, int> buckets;
    for (const auto &shortHist: mHists) {
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
    // TODO: print reader (author) ID
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
          body->appendFormat("%.*s%s", colWidth - 1,
                             spaces.c_str(), x.second < value ? " " : "|");
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


// TODO: decide whether to use this or whether it is overkill, and it is enough
// to only treat as glitches single wakeup call intervals which are too long.
// Ultimately, glitch detection will be directly on the audio signal.
// Produces a log warning if the timing of recent buffer periods caused a glitch
// Computes sum of running window of three buffer periods
// Checks whether the buffer periods leave enough CPU time for the next one
// e.g. if a buffer period is expected to be 4 ms and a buffer requires 3 ms of CPU time,
// here are some glitch cases:
// 4 + 4 + 6 ; 5 + 4 + 5; 2 + 2 + 10
void PerformanceAnalysis::alertIfGlitch(const std::vector<int64_t> &samples) {
    std::deque<int> periods(kNumBuff, kPeriodMs);
    for (size_t i = 2; i < samples.size(); ++i) { // skip first time entry
        periods.push_front(deltaMs(samples[i - 1], samples[i]));
        periods.pop_back();
        // TODO: check that all glitch cases are covered
        if (std::accumulate(periods.begin(), periods.end(), 0) > kNumBuff * kPeriodMs +
            kPeriodMs - kPeriodMsCPU) {
                periods.assign(kNumBuff, kPeriodMs);
        }
    }
    return;
}

//------------------------------------------------------------------------------

// writes summary of performance into specified file descriptor
void dump(int fd, int indent, PerformanceAnalysisMap &threadPerformanceAnalysis) {
    String8 body;
    const char* const kDirectory = "/data/misc/audioserver/";
    for (auto & thread : threadPerformanceAnalysis) {
        for (auto & hash: thread.second) {
            PerformanceAnalysis& curr = hash.second;
            // write performance data to console
            curr.reportPerformance(&body);
            if (!body.isEmpty()) {
                dumpLine(fd, indent, body);
                body.clear();
            }
            // write to file
            writeToFile(curr.mHists, curr.mOutlierData, curr.mPeakTimestamps,
                        kDirectory, false, thread.first, hash.first);
        }
    }
}


// Writes a string into specified file descriptor
void dumpLine(int fd, int indent, const String8 &body) {
    dprintf(fd, "%.*s%s \n", indent, "", body.string());
}

} // namespace ReportPerformance

}   // namespace android
