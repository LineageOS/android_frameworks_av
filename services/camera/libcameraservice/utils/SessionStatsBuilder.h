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

#ifndef ANDROID_SERVICE_UTILS_SESSION_STATS_BUILDER_H
#define ANDROID_SERVICE_UTILS_SESSION_STATS_BUILDER_H

#include <utils/Errors.h>

#include <mutex>
#include <map>

namespace android {

// Helper class to build stream stats
struct StreamStats {
    int64_t mRequestedFrameCount;
    int64_t mDroppedFrameCount;
    bool mCounterStopped;
    int32_t mStartLatencyMs;

    StreamStats() : mRequestedFrameCount(0),
                     mDroppedFrameCount(0),
                     mCounterStopped(false),
                     mStartLatencyMs(0) {}
};

// Helper class to build session stats
class SessionStatsBuilder {
public:

    status_t addStream(int streamId);
    status_t removeStream(int streamId);

    // Return the session statistics and reset the internal states.
    void buildAndReset(/*out*/int64_t* requestCount,
            /*out*/int64_t* errorResultCount,
            /*out*/bool* deviceError,
            /*out*/std::map<int, StreamStats> *statsMap);

    // Stream specific counter
    void startCounter(int streamId);
    void stopCounter(int streamId);
    void incCounter(int streamId, bool dropped, int32_t captureLatencyMs);

    // Session specific counter
    void stopCounter();
    void incResultCounter(bool dropped);
    void onDeviceError();

    SessionStatsBuilder() : mRequestCount(0), mErrorResultCount(0),
             mCounterStopped(false), mDeviceError(false) {}
private:
    std::mutex mLock;
    int64_t mRequestCount;
    int64_t mErrorResultCount;
    bool mCounterStopped;
    bool mDeviceError;
    // Map from stream id to stream statistics
    std::map<int, StreamStats> mStatsMap;
};

}; // namespace android

#endif // ANDROID_SERVICE_UTILS_SESSION_STATS_BUILDER_H
