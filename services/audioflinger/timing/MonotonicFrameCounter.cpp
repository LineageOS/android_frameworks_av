/*
 * Copyright (C) 2022 The Android Open Source Project
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

// #define LOG_NDEBUG 0
#define LOG_TAG "MonotonicFrameCounter"

#include <utils/Log.h>
#include "MonotonicFrameCounter.h"

namespace android::audioflinger {

int64_t MonotonicFrameCounter::updateAndGetMonotonicFrameCount(
        int64_t newFrameCount, int64_t newTime) {
    if (newFrameCount < 0 || newTime < 0) {
        const auto result = getLastReportedFrameCount();
        ALOGW("%s: invalid (frame, time) pair newFrameCount:%lld newFrameCount:%lld,"
                " using %lld as frameCount",
                __func__, (long long) newFrameCount, (long long)newFrameCount,
                (long long)result);
        return result;
    }
    if (newFrameCount < mLastReceivedFrameCount) {
        const auto result = getLastReportedFrameCount();
        ALOGW("%s: retrograde newFrameCount:%lld < mLastReceivedFrameCount:%lld,"
                " ignoring, returning %lld as frameCount",
                __func__, (long long) newFrameCount, (long long)mLastReceivedFrameCount,
                (long long)result);
        return result;
    }
    // Input looks fine.
    // For better granularity, we could consider extrapolation on newTime.
    mLastReceivedFrameCount = newFrameCount;
    return getLastReportedFrameCount();
}

int64_t MonotonicFrameCounter::onFlush() {
    ALOGV("%s: Updating mOffsetFrameCount:%lld with mLastReceivedFrameCount:%lld",
            __func__, (long long)mOffsetFrameCount, (long long)mLastReceivedFrameCount);
    mOffsetFrameCount += mLastReceivedFrameCount;
    mLastReceivedFrameCount = 0;
    return mOffsetFrameCount;
}

} // namespace android::audioflinger
