/*
 * Copyright (C) 2023 The Android Open Source Project
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

#include <android-base/stringprintf.h>
#include <android-base/thread_annotations.h>
#include <audio_utils/SimpleLog.h>
#include <chrono>
#include <math.h>
#include <mutex>
#include <vector>

namespace android::media {

/**
 * VectorRecorder records a vector of floats computing the average, max, and min
 * over given time periods.
 *
 * The class is thread-safe.
 */
class VectorRecorder {
  public:
    VectorRecorder(
        size_t vectorSize, std::chrono::duration<double> threshold, int maxLogLine)
        : mVectorSize(vectorSize)
        , mRecordLog(maxLogLine)
        , mRecordThreshold(threshold)
    {
        resetRecord_l();  // OK to call - we're in the constructor.
    }

    /** Convert recorded vector data to string with level indentation */
    std::string toString(size_t indent) const;

    /**
     * @brief Record a vector of floats.
     *
     * @param record a vector of floats.
     */
    void record(const std::vector<float>& record);

    /**
     * Format vector to a string, [0.00, 0.00, 0.00, -1.29, -0.50, 15.27].
     */
    template <typename T>
    static std::string toString(const std::vector<T>& record) {
        if (record.size() == 0) {
            return "[]";
        }

        std::string ss = "[";
        for (size_t i = 0; i < record.size(); ++i) {
            if (i > 0) {
                ss.append(", ");
            }
            base::StringAppendF(&ss, "%0.2lf", static_cast<double>(record[i]));
        }
        ss.append("]");
        return ss;
    }

  private:
    static constexpr int mMaxLocalLogLine = 10;

    const size_t mVectorSize;

    // Local log for historical vector data.
    // Locked internally, so does not need mutex below.
    SimpleLog mRecordLog{mMaxLocalLogLine};

    std::mutex mLock;

    // Time threshold to record vectors in the local log.
    // Vector data will be recorded into log at least every mRecordThreshold.
    std::chrono::duration<double> mRecordThreshold GUARDED_BY(mLock);

    // Number of seconds since first sample in mSum.
    std::chrono::duration<double> mNumberOfSecondsSinceFirstSample GUARDED_BY(mLock);

    // Timestamp of first sample recorded in mSum.
    std::chrono::time_point<std::chrono::steady_clock> mFirstSampleTimestamp GUARDED_BY(mLock);

    // Number of samples in mSum.
    size_t mNumberOfSamples GUARDED_BY(mLock) = 0;

    std::vector<double> mSum GUARDED_BY(mLock);
    std::vector<float> mMax GUARDED_BY(mLock);
    std::vector<float> mMin GUARDED_BY(mLock);

    // Computes mNumberOfSecondsSinceFirstSample, returns true if time to record.
    bool shouldRecordLog_l() REQUIRES(mLock);

    // Resets the running mNumberOfSamples, mSum, mMax, mMin.
    void resetRecord_l() REQUIRES(mLock);

    // Convert mSum to an average.
    void sumToAverage_l() REQUIRES(mLock);
};  // VectorRecorder

}  // namespace android::media
