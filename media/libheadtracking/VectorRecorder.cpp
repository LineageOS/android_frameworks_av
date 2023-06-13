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

#include "media/VectorRecorder.h"

namespace android::media {

// Convert data to string with level indentation.
// No need for a lock as the SimpleLog is thread-safe.
std::string VectorRecorder::toString(size_t indent) const {
    return mRecordLog.dumpToString(std::string(indent, ' ').c_str(), mMaxLocalLogLine);
}

// Record into local log when it is time.
void VectorRecorder::record(const std::vector<float>& record) {
    if (record.size() != mVectorSize) return;

    // Protect against concurrent calls to record().
    std::lock_guard lg(mLock);

    // if it is time, record average data and reset.
    if (shouldRecordLog_l()) {
        sumToAverage_l();
        mRecordLog.log(
                "mean: %s, min: %s, max %s, calculated %zu samples in %0.4f second(s)",
                toString(mSum, mDelimiterIdx, mFormatString.c_str()).c_str(),
                toString(mMin, mDelimiterIdx, mFormatString.c_str()).c_str(),
                toString(mMax, mDelimiterIdx, mFormatString.c_str()).c_str(),
                mNumberOfSamples,
                mNumberOfSecondsSinceFirstSample.count());
        resetRecord_l();
    }

    // update stream average.
    if (mNumberOfSamples++ == 0) {
        mFirstSampleTimestamp = std::chrono::steady_clock::now();
        for (size_t i = 0; i < mVectorSize; ++i) {
            const float value = record[i];
            mSum[i] += value;
            mMax[i] = value;
            mMin[i] = value;
        }
    } else {
        for (size_t i = 0; i < mVectorSize; ++i) {
            const float value = record[i];
            mSum[i] += value;
            mMax[i] = std::max(mMax[i], value);
            mMin[i] = std::min(mMin[i], value);
        }
    }
}

bool VectorRecorder::shouldRecordLog_l() {
    mNumberOfSecondsSinceFirstSample = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - mFirstSampleTimestamp);
    return mNumberOfSecondsSinceFirstSample >= mRecordThreshold;
}

void VectorRecorder::resetRecord_l() {
    mSum.assign(mVectorSize, 0);
    mMax.assign(mVectorSize, 0);
    mMin.assign(mVectorSize, 0);
    mNumberOfSamples = 0;
    mNumberOfSecondsSinceFirstSample = std::chrono::seconds(0);
}

void VectorRecorder::sumToAverage_l() {
    if (mNumberOfSamples == 0) return;
    const float reciprocal = 1.f / mNumberOfSamples;
    for (auto& p : mSum) {
        p *= reciprocal;
    }
}

}  // namespace android::media
