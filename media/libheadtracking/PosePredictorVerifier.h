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

#include <string>

#include <audio_utils/Statistics.h>
#include <media/Pose.h>

namespace android::media {

/**
 * PosePredictorVerifier is used to validate predictions
 *
 * This class is not thread-safe
 */
class PosePredictorVerifier {
public:
    std::string toString() const {
         return mErrorStats.toString();
    }

    static constexpr int64_t kMillisToNanos = 1000000;

    void verifyActualPose(int64_t timestampNs, const Pose3f& pose) {
        for (auto it = mPredictions.begin(); it != mPredictions.end();) {
            if (it->first < timestampNs) {
                it = mPredictions.erase(it);
            } else {
                int64_t dt = it->first - timestampNs;
                if (std::abs(dt) < 10 * kMillisToNanos) {
                    const float angle = pose.rotation().angularDistance(it->second.rotation());
                    const float error = std::abs(angle); // L1 (absolute difference) here.
                    mLastError = error;
                    mErrorStats.add(error);
                }
                break;
            }
        }
    }

    void addPredictedPose(int64_t atNs, const Pose3f& pose) {
        mPredictions.emplace_back(atNs, pose);
    }

    float lastError() const {
        return mLastError;
    }

    float cumulativeAverageError() const {
        return mErrorStats.getMean();
    }

private:
    static constexpr double kCumulativeErrorAlpha = 0.999;
    std::deque<std::pair<int64_t, Pose3f>> mPredictions;
    float mLastError{};
    android::audio_utils::Statistics<double> mErrorStats{kCumulativeErrorAlpha};
};

}  // namespace androd::media
