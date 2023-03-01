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
    /**
     * @param vectorSize is the size of the vector input.
     *        If the input does not match this size, it is ignored.
     * @param threshold is the time interval we bucket for averaging.
     * @param maxLogLine is the number of lines we log.  At this
     *        threshold, the oldest line will expire when the new line comes in.
     * @param delimiterIdx is an optional array of delimiter indices that
     *        replace the ',' with a ':'.  For example if delimiterIdx = { 3 } then
     *        the above example would format as [0.00, 0.00, 0.00 : -1.29, -0.50, 15.27].
     * @param formatString is the sprintf format string for the double converted data
     *        to use.
     */
    VectorRecorder(
        size_t vectorSize, std::chrono::duration<double> threshold, int maxLogLine,
            std::vector<size_t> delimiterIdx = {},
            const std::string_view formatString = {})
        : mVectorSize(vectorSize)
        , mDelimiterIdx(std::move(delimiterIdx))
        , mFormatString(formatString)
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
     *
     * @param delimiterIdx is an optional array of delimiter indices that
     *        replace the ',' with a ':'.  For example if delimiterIdx = { 3 } then
     *        the above example would format as [0.00, 0.00, 0.00 : -1.29, -0.50, 15.27].
     * @param formatString is the sprintf format string for the double converted data
     *        to use.
     */
    template <typename T>
    static std::string toString(const std::vector<T>& record,
            const std::vector<size_t>& delimiterIdx = {},
            const char * const formatString = nullptr) {
        if (record.size() == 0) {
            return "[]";
        }

        std::string ss = "[";
        auto nextDelimiter = delimiterIdx.begin();
        for (size_t i = 0; i < record.size(); ++i) {
            if (i > 0) {
                if (nextDelimiter != delimiterIdx.end()
                        && *nextDelimiter <= i) {
                     ss.append(" : ");
                     ++nextDelimiter;
                } else {
                    ss.append(", ");
                }
            }
            if (formatString != nullptr && *formatString) {
                base::StringAppendF(&ss, formatString, static_cast<double>(record[i]));
            } else {
                base::StringAppendF(&ss, "%5.2lf", static_cast<double>(record[i]));
            }
        }
        ss.append("]");
        return ss;
    }

  private:
    static constexpr int mMaxLocalLogLine = 10;

    const size_t mVectorSize;
    const std::vector<size_t> mDelimiterIdx;
    const std::string mFormatString;

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
