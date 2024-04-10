/*
 * Copyright (C) 2020 The Android Open Source Project
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

#define LOG_TAG "CameraSessionStatsBuilder"
#define ATRACE_TAG ATRACE_TAG_CAMERA
//#define LOG_NDEBUG 0

#include <numeric>

#include <inttypes.h>
#include <utils/Log.h>

#include "SessionStatsBuilder.h"

namespace android {

// Bins for capture latency: [0, 100], [100, 200], [200, 300], ...
// [1300, 2100], [2100, inf].
// Capture latency is in the unit of millisecond.
const std::array<int32_t, StreamStats::LATENCY_BIN_COUNT-1> StreamStats::mCaptureLatencyBins {
        { 100, 200, 300, 400, 500, 700, 900, 1300, 2100 } };

status_t SessionStatsBuilder::addStream(int id) {
    std::lock_guard<std::mutex> l(mLock);
    StreamStats stats;
    mStatsMap.emplace(id, stats);
    return OK;
}

status_t SessionStatsBuilder::removeStream(int id) {
    std::lock_guard<std::mutex> l(mLock);
    mStatsMap.erase(id);
    return OK;
}

void SessionStatsBuilder::buildAndReset(int64_t* requestCount,
        int64_t* errorResultCount, bool* deviceError,
        std::pair<int32_t, int32_t>* mostRequestedFpsRange,
        std::map<int, StreamStats>* statsMap) {
    std::lock_guard<std::mutex> l(mLock);
    *requestCount = mRequestCount;
    *errorResultCount = mErrorResultCount;
    *deviceError = mDeviceError;
    *statsMap = mStatsMap;

    int32_t minFps = 0, maxFps = 0;
    if (mRequestedFpsRangeHistogram.size() > 0) {
        auto mostCommonIt = mRequestedFpsRangeHistogram.begin();
        for (auto it = mostCommonIt; it != mRequestedFpsRangeHistogram.end(); it++) {
            if (it->second.first > mostCommonIt->second.first) {
                mostCommonIt = it;
            }
        }
        minFps = mostCommonIt->first >> 32;
        maxFps = mostCommonIt->first & 0xFFFF'FFFFU;
    }
    *mostRequestedFpsRange = std::make_pair(minFps, maxFps);

    // Reset internal states
    mRequestCount = 0;
    mErrorResultCount = 0;
    mCounterStopped = false;
    mDeviceError = false;
    mUserTag.clear();
    mRequestedFpsRangeHistogram.clear();

    for (auto& streamStats : mStatsMap) {
        StreamStats& streamStat = streamStats.second;
        streamStat.mRequestedFrameCount = 0;
        streamStat.mDroppedFrameCount = 0;
        streamStat.mCounterStopped = false;
        streamStat.mStartLatencyMs = 0;

        std::fill(streamStat.mCaptureLatencyHistogram.begin(),
                streamStat.mCaptureLatencyHistogram.end(), 0);
    }
}

void SessionStatsBuilder::startCounter(int id) {
    std::lock_guard<std::mutex> l(mLock);
    mStatsMap[id].mCounterStopped = false;
}

void SessionStatsBuilder::stopCounter(int id) {
    std::lock_guard<std::mutex> l(mLock);
    StreamStats& streamStat = mStatsMap[id];
    streamStat.mCounterStopped = true;
}

void SessionStatsBuilder::incCounter(int id, bool dropped, int32_t captureLatencyMs) {
    std::lock_guard<std::mutex> l(mLock);

    auto it = mStatsMap.find(id);
    if (it == mStatsMap.end()) return;

    StreamStats& streamStat = it->second;
    if (streamStat.mCounterStopped) return;

    streamStat.mRequestedFrameCount++;
    if (dropped) {
        streamStat.mDroppedFrameCount++;
    } else if (streamStat.mRequestedFrameCount - streamStat.mDroppedFrameCount == 1) {
        // The capture latency for the first request.
        streamStat.mStartLatencyMs = captureLatencyMs;
    }

    streamStat.updateLatencyHistogram(captureLatencyMs);
}

void SessionStatsBuilder::stopCounter() {
    std::lock_guard<std::mutex> l(mLock);
    mCounterStopped = true;
    for (auto& streamStats : mStatsMap) {
        streamStats.second.mCounterStopped = true;
    }
}

void SessionStatsBuilder::incResultCounter(bool dropped) {
    std::lock_guard<std::mutex> l(mLock);
    if (mCounterStopped) return;

    mRequestCount++;
    if (dropped) mErrorResultCount++;
}

void SessionStatsBuilder::onDeviceError() {
    std::lock_guard<std::mutex> l(mLock);
    mDeviceError = true;
}

void SessionStatsBuilder::incFpsRequestedCount(int32_t minFps, int32_t maxFps,
        int64_t frameNumber) {
    std::lock_guard<std::mutex> l(mLock);

    // Stuff range into a 64-bit value to make hashing simple
    uint64_t currentFpsTarget = minFps;
    currentFpsTarget = currentFpsTarget << 32 | maxFps;

    auto &stats = mRequestedFpsRangeHistogram[currentFpsTarget];
    stats.first++;
    stats.second = frameNumber;

    // Ensure weird app input of target FPS ranges doesn't cause unbounded memory growth
    if (mRequestedFpsRangeHistogram.size() > FPS_HISTOGRAM_MAX_SIZE) {
        // Find oldest used fps to drop by last seen frame number
        auto deleteIt = mRequestedFpsRangeHistogram.begin();
        for (auto it = deleteIt; it != mRequestedFpsRangeHistogram.end(); it++) {
            if (it->second.second < deleteIt->second.second) {
                deleteIt = it;
            }
        }
        mRequestedFpsRangeHistogram.erase(deleteIt);
    }
}

void StreamStats::updateLatencyHistogram(int32_t latencyMs) {
    size_t i;
    for (i = 0; i < mCaptureLatencyBins.size(); i++) {
        if (latencyMs < mCaptureLatencyBins[i]) {
            mCaptureLatencyHistogram[i] ++;
            break;
        }
    }

    if (i == mCaptureLatencyBins.size()) {
        mCaptureLatencyHistogram[i]++;
    }
}

}; // namespace android
