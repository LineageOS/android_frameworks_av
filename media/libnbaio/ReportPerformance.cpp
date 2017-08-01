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

#define LOG_TAG "ReportPerformance"

#include <fstream>
#include <iostream>
#include <queue>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sstream>
#include <sys/prctl.h>
#include <utility>
#include <media/nbaio/NBLog.h>
#include <media/nbaio/PerformanceAnalysis.h>
#include <media/nbaio/ReportPerformance.h>
#include <utils/Log.h>
#include <utils/String8.h>

namespace android {

namespace ReportPerformance {

// Writes outlier intervals, timestamps, and histograms spanning long time intervals to a file.
// TODO: format the data efficiently and write different types of data to different files
void writeToFile(const std::deque<std::pair<timestamp, Histogram>> &hists,
                 const std::deque<std::pair<msInterval, timestamp>> &outlierData,
                 const std::deque<timestamp> &peakTimestamps,
                 const char * directory, bool append, int author, log_hash_t hash) {
    if (outlierData.empty() || hists.empty()) {
        ALOGW("No data, returning.");
        return;
    }

    std::stringstream outlierName;
    std::stringstream histogramName;
    std::stringstream peakName;

    histogramName << directory << "histograms_" << author << "_" << hash;
    outlierName << directory << "outliers_" << author << "_" << hash;
    peakName << directory << "peaks_" << author << "_" << hash;

    std::ofstream hfs;
    hfs.open(histogramName.str(), append ? std::ios::app : std::ios::trunc);
    if (!hfs.is_open()) {
        ALOGW("couldn't open file %s", histogramName.str().c_str());
        return;
    }
    hfs << "Histogram data\n";
    for (const auto &hist : hists) {
        hfs << "\ttimestamp\n";
        hfs << hist.first << "\n";
        hfs << "\tbuckets (in ms) and counts\n";
        for (const auto &bucket : hist.second) {
            hfs << bucket.first / static_cast<double>(kJiffyPerMs)
                    << ": " << bucket.second << "\n";
        }
        hfs << "\n"; // separate histograms with a newline
    }
    hfs.close();

    std::ofstream ofs;
    ofs.open(outlierName.str(), append ? std::ios::app : std::ios::trunc);
    if (!ofs.is_open()) {
        ALOGW("couldn't open file %s", outlierName.str().c_str());
        return;
    }
    ofs << "Outlier data: interval and timestamp\n";
    for (const auto &outlier : outlierData) {
        ofs << outlier.first << ": " << outlier.second << "\n";
    }
    ofs.close();

    std::ofstream pfs;
    pfs.open(peakName.str(), append ? std::ios::app : std::ios::trunc);
    if (!pfs.is_open()) {
        ALOGW("couldn't open file %s", peakName.str().c_str());
        return;
    }
    pfs << "Peak data: timestamp\n";
    for (const auto &peak : peakTimestamps) {
        pfs << peak << "\n";
    }
    pfs.close();
}

} // namespace ReportPerformance

}   // namespace android
