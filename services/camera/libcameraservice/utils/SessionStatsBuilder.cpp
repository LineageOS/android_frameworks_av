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

#include <utils/Log.h>

#include "SessionStatsBuilder.h"

namespace android {

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
        std::map<int, StreamStats> *statsMap) {
    std::lock_guard<std::mutex> l(mLock);
    *requestCount = mRequestCount;
    *errorResultCount = mErrorResultCount;
    *deviceError = mDeviceError;
    *statsMap = mStatsMap;

    // Reset internal states
    mRequestCount = 0;
    mErrorResultCount = 0;
    mCounterStopped = false;
    mDeviceError = false;
    for (auto& streamStats : mStatsMap) {
        streamStats.second.mRequestedFrameCount = 0;
        streamStats.second.mDroppedFrameCount = 0;
        streamStats.second.mCounterStopped = false;
        streamStats.second.mStartLatencyMs = 0;
    }
}

void SessionStatsBuilder::startCounter(int id) {
    std::lock_guard<std::mutex> l(mLock);
    mStatsMap[id].mCounterStopped = false;
}

void SessionStatsBuilder::stopCounter(int id) {
    std::lock_guard<std::mutex> l(mLock);
    mStatsMap[id].mCounterStopped = true;
}

void SessionStatsBuilder::incCounter(int id, bool dropped, int32_t captureLatencyMs) {
    std::lock_guard<std::mutex> l(mLock);
    auto it = mStatsMap.find(id);
    if (it != mStatsMap.end()) {
         if (!it->second.mCounterStopped) {
             it->second.mRequestedFrameCount++;
             if (dropped) {
                 it->second.mDroppedFrameCount++;
             } else if (it->second.mRequestedFrameCount == 1) {
                 // The capture latency for the first request.
                 it->second.mStartLatencyMs = captureLatencyMs;
             }
         }
    }
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
    if (!mCounterStopped) {
        mRequestCount ++;
        if (dropped) mErrorResultCount++;
    }
}

void SessionStatsBuilder::onDeviceError() {
    std::lock_guard<std::mutex> l(mLock);
    mDeviceError = true;
}

}; // namespace android
