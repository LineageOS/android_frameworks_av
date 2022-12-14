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

#pragma once

#include <cstdint>

namespace android::audioflinger {

/**
 * MonotonicFrameCounter
 *
 * Advances a monotonic frame count based on input timestamp pairs (frames, time).
 * It takes into account a possible flush, which will "reset" the frames to 0.
 *
 * This class is used to drive VolumeShaper volume automation.
 *
 * The timestamps provided in updateAndGetMonotonicFrameCount should
 * be of sufficient granularity for the purpose at hand.  Currently no temporal
 * extrapolation is done.
 *
 * This class is not thread safe.
 */
class MonotonicFrameCounter {
public:
    /**
     * Receives a new timestamp pair (frames, time) and returns a monotonic frameCount.
     *
     * \param newFrameCount the frameCount currently played.
     * \param newTime       the time corresponding to the frameCount.
     * \return              a monotonic frame count usable for automation timing.
     */
    int64_t updateAndGetMonotonicFrameCount(int64_t newFrameCount, int64_t newTime);

    /**
     * Notifies when a flush occurs, whereupon the received frameCount sequence restarts at 0.
     *
     * \return the last reported frameCount.
     */
    int64_t onFlush();

    /**
     * Returns the received (input) frameCount to reported (output) frameCount offset.
     *
     * This offset is sufficient to ensure monotonicity after flush is called,
     * suitability for any other purpose is *not* guaranteed.
     */
    int64_t getOffsetFrameCount() const { return mOffsetFrameCount; }

    /**
     * Returns the last received frameCount.
     */
    int64_t getLastReceivedFrameCount() const {
        return mLastReceivedFrameCount;
    }

    /**
     * Returns the last reported frameCount from updateAndGetMonotonicFrameCount().
     */
    int64_t getLastReportedFrameCount() const {
        // This is consistent after onFlush().
        return mOffsetFrameCount + mLastReceivedFrameCount;
    }

private:
    int64_t mOffsetFrameCount = 0;
    int64_t mLastReceivedFrameCount = 0;
};

} // namespace android::audioflinger
