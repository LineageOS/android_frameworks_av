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
//#define LOG_NDEBUG 0

#include <fstream>
#include <iostream>
#include <memory>
#include <queue>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sstream>
#include <sys/prctl.h>
#include <sys/time.h>
#include <utility>
#include <json/json.h>
#include <media/MediaAnalyticsItem.h>
#include <media/nblog/Events.h>
#include <media/nblog/PerformanceAnalysis.h>
#include <media/nblog/ReportPerformance.h>
#include <utils/Log.h>
#include <utils/String8.h>

namespace android {
namespace ReportPerformance {

std::unique_ptr<Json::Value> dumpToJson(const PerformanceData& data)
{
    std::unique_ptr<Json::Value> rootPtr = std::make_unique<Json::Value>(Json::objectValue);
    Json::Value& root = *rootPtr;
    root["type"] = (Json::Value::Int)data.threadInfo.type;
    root["frameCount"] = (Json::Value::Int)data.threadInfo.frameCount;
    root["sampleRate"] = (Json::Value::Int)data.threadInfo.sampleRate;
    root["workMsHist"] = data.workHist.toString();
    root["latencyMsHist"] = data.latencyHist.toString();
    root["warmupMsHist"] = data.warmupHist.toString();
    root["underruns"] = (Json::Value::Int64)data.underruns;
    root["overruns"] = (Json::Value::Int64)data.overruns;
    root["activeMs"] = (Json::Value::Int64)ns2ms(data.active);
    root["durationMs"] = (Json::Value::Int64)ns2ms(systemTime() - data.start);
    return rootPtr;
}

bool sendToMediaMetrics(const PerformanceData& data)
{
    // See documentation for these metrics here:
    // docs.google.com/document/d/11--6dyOXVOpacYQLZiaOY5QVtQjUyqNx2zT9cCzLKYE/edit?usp=sharing
    static constexpr char kThreadType[] = "android.media.audiothread.type";
    static constexpr char kThreadFrameCount[] = "android.media.audiothread.framecount";
    static constexpr char kThreadSampleRate[] = "android.media.audiothread.samplerate";
    static constexpr char kThreadWorkHist[] = "android.media.audiothread.workMs.hist";
    static constexpr char kThreadLatencyHist[] = "android.media.audiothread.latencyMs.hist";
    static constexpr char kThreadWarmupHist[] = "android.media.audiothread.warmupMs.hist";
    static constexpr char kThreadUnderruns[] = "android.media.audiothread.underruns";
    static constexpr char kThreadOverruns[] = "android.media.audiothread.overruns";
    static constexpr char kThreadActive[] = "android.media.audiothread.activeMs";
    static constexpr char kThreadDuration[] = "android.media.audiothread.durationMs";

    std::unique_ptr<MediaAnalyticsItem> item(new MediaAnalyticsItem("audiothread"));

    const Histogram &workHist = data.workHist;
    if (workHist.totalCount() > 0) {
        item->setCString(kThreadWorkHist, workHist.toString().c_str());
    }

    const Histogram &latencyHist = data.latencyHist;
    if (latencyHist.totalCount() > 0) {
        item->setCString(kThreadLatencyHist, latencyHist.toString().c_str());
    }

    const Histogram &warmupHist = data.warmupHist;
    if (warmupHist.totalCount() > 0) {
        item->setCString(kThreadWarmupHist, warmupHist.toString().c_str());
    }

    if (data.underruns > 0) {
        item->setInt64(kThreadUnderruns, data.underruns);
    }

    if (data.overruns > 0) {
        item->setInt64(kThreadOverruns, data.overruns);
    }

    // Send to Media Metrics if the record is not empty.
    // The thread and time info are added inside the if statement because
    // we want to send them only if there are performance metrics to send.
    if (item->count() > 0) {
        // Add thread info fields.
        const char * const typeString = NBLog::threadTypeToString(data.threadInfo.type);
        item->setCString(kThreadType, typeString);
        item->setInt32(kThreadFrameCount, data.threadInfo.frameCount);
        item->setInt32(kThreadSampleRate, data.threadInfo.sampleRate);
        // Add time info fields.
        item->setInt64(kThreadActive, data.active / 1000000);
        item->setInt64(kThreadDuration, (systemTime() - data.start) / 1000000);
        return item->selfrecord();
    }
    return false;
}

//------------------------------------------------------------------------------

// TODO: use a function like this to extract logic from writeToFile
// https://stackoverflow.com/a/9279620

// Writes outlier intervals, timestamps, and histograms spanning long time intervals to file.
// TODO: write data in binary format
void writeToFile(const std::deque<std::pair<timestamp, Hist>> &hists,
                 const std::deque<std::pair<msInterval, timestamp>> &outlierData,
                 const std::deque<timestamp> &peakTimestamps,
                 const char * directory, bool append, int author, log_hash_t hash) {

    // TODO: remove old files, implement rotating files as in AudioFlinger.cpp

    if (outlierData.empty() && hists.empty() && peakTimestamps.empty()) {
        ALOGW("No data, returning.");
        return;
    }

    std::stringstream outlierName;
    std::stringstream histogramName;
    std::stringstream peakName;

    // get current time
    char currTime[16]; //YYYYMMDDHHMMSS + '\0' + one unused
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm tm;
    localtime_r(&tv.tv_sec, &tm);
    strftime(currTime, sizeof(currTime), "%Y%m%d%H%M%S", &tm);

    // generate file names
    std::stringstream common;
    common << author << "_" << hash << "_" << currTime << ".csv";

    histogramName << directory << "histograms_" << common.str();
    outlierName << directory << "outliers_" << common.str();
    peakName << directory << "peaks_" << common.str();

    std::ofstream hfs;
    hfs.open(histogramName.str(), append ? std::ios::app : std::ios::trunc);
    if (!hfs.is_open()) {
        ALOGW("couldn't open file %s", histogramName.str().c_str());
        return;
    }
    // each histogram is written as a line where the first value is the timestamp and
    // subsequent values are pairs of buckets and counts. Each value is separated
    // by a comma, and each histogram is separated by a newline.
    for (auto hist = hists.begin(); hist != hists.end(); ++hist) {
        hfs << hist->first << ", ";
        for (auto bucket = hist->second.begin(); bucket != hist->second.end(); ++bucket) {
            hfs << bucket->first / static_cast<double>(kJiffyPerMs)
                << ", " << bucket->second;
            if (std::next(bucket) != end(hist->second)) {
                hfs << ", ";
            }
        }
        if (std::next(hist) != end(hists)) {
            hfs << "\n";
        }
    }
    hfs.close();

    std::ofstream ofs;
    ofs.open(outlierName.str(), append ? std::ios::app : std::ios::trunc);
    if (!ofs.is_open()) {
        ALOGW("couldn't open file %s", outlierName.str().c_str());
        return;
    }
    // outliers are written as pairs separated by newlines, where each
    // pair's values are separated by a comma
    for (const auto &outlier : outlierData) {
        ofs << outlier.first << ", " << outlier.second << "\n";
    }
    ofs.close();

    std::ofstream pfs;
    pfs.open(peakName.str(), append ? std::ios::app : std::ios::trunc);
    if (!pfs.is_open()) {
        ALOGW("couldn't open file %s", peakName.str().c_str());
        return;
    }
    // peaks are simply timestamps separated by commas
    for (auto peak = peakTimestamps.begin(); peak != peakTimestamps.end(); ++peak) {
        pfs << *peak;
        if (std::next(peak) != end(peakTimestamps)) {
            pfs << ", ";
        }
    }
    pfs.close();
}

}   // namespace ReportPerformance
}   // namespace android
