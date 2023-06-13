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

#include "PosePredictor.h"

namespace android::media {

namespace {
#ifdef ENABLE_VERIFICATION
constexpr bool kEnableVerification = true;
constexpr std::array<int, 3> kLookAheadMs{ 50, 100, 200 };
#else
constexpr bool kEnableVerification = false;
constexpr std::array<int, 0> kLookAheadMs{};
#endif

} // namespace

void LeastSquaresPredictor::add(int64_t atNs, const Pose3f& pose, const Twist3f& twist)
{
    (void)twist;
    mLastAtNs = atNs;
    mLastPose = pose;
    const auto q = pose.rotation();
    const double datNs = static_cast<double>(atNs);
    mRw.add({datNs, q.w()});
    mRx.add({datNs, q.x()});
    mRy.add({datNs, q.y()});
    mRz.add({datNs, q.z()});
}

Pose3f LeastSquaresPredictor::predict(int64_t atNs) const
{
    if (mRw.getN() < kMinimumSamplesForPrediction) return mLastPose;

    /*
     * Using parametric form, we have q(t) = { w(t), x(t), y(t), z(t) }.
     * We compute the least squares prediction of w, x, y, z.
     */
    const double dLookahead = static_cast<double>(atNs);
    Eigen::Quaternionf lsq(
        mRw.getYFromX(dLookahead),
        mRx.getYFromX(dLookahead),
        mRy.getYFromX(dLookahead),
        mRz.getYFromX(dLookahead));

     /*
      * We cheat here, since the result lsq is the least squares prediction
      * in H (arbitrary quaternion), not the least squares prediction in
      * SO(3) (unit quaternion).
      *
      * In other words, the result for lsq is most likely not a unit quaternion.
      * To solve this, we normalize, thereby selecting the closest unit quaternion
      * in SO(3) to the prediction in H.
      */
    lsq.normalize();
    return Pose3f(lsq);
}

void LeastSquaresPredictor::reset() {
    mLastAtNs = {};
    mLastPose = {};
    mRw.reset();
    mRx.reset();
    mRy.reset();
    mRz.reset();
}

std::string LeastSquaresPredictor::toString(size_t index) const {
    std::string s(index, ' ');
    s.append("LeastSquaresPredictor using alpha: ")
        .append(std::to_string(mAlpha))
        .append(" last pose: ")
        .append(mLastPose.toString())
        .append("\n");
    return s;
}

// Formatting
static inline std::vector<size_t> createDelimiterIdx(size_t predictors, size_t lookaheads) {
    if (lookaheads == 0) return {};
    --lookaheads;
    std::vector<size_t> delimiterIdx(lookaheads);
    for (size_t i = 0; i < lookaheads; ++i) {
        delimiterIdx[i] = (i + 1) * predictors;
    }
    return delimiterIdx;
}

PosePredictor::PosePredictor()
    : mPredictors{
            // First predictors must match switch in getCurrentPredictor()
            std::make_shared<LastPredictor>(),
            std::make_shared<TwistPredictor>(),
            std::make_shared<LeastSquaresPredictor>(),
            // After this, can place additional predictors here for comparison such as
            // std::make_shared<LeastSquaresPredictor>(0.25),
        }
    , mLookaheadMs(kLookAheadMs.begin(), kLookAheadMs.end())
    , mVerifiers(std::size(mLookaheadMs) * std::size(mPredictors))
    , mDelimiterIdx(createDelimiterIdx(std::size(mPredictors), std::size(mLookaheadMs)))
    , mPredictionRecorder(
        std::size(mVerifiers) /* vectorSize */, std::chrono::seconds(1), 10 /* maxLogLine */,
        mDelimiterIdx)
    , mPredictionDurableRecorder(
        std::size(mVerifiers) /* vectorSize */, std::chrono::minutes(1), 10 /* maxLogLine */,
        mDelimiterIdx)
    {
}

Pose3f PosePredictor::predict(
        int64_t timestampNs, const Pose3f& pose, const Twist3f& twist, float predictionDurationNs)
{
    if (timestampNs - mLastTimestampNs > kMaximumSampleIntervalBeforeResetNs) {
        for (const auto& predictor : mPredictors) {
            predictor->reset();
        }
        ++mResets;
    }
    mLastTimestampNs = timestampNs;

    auto selectedPredictor = getCurrentPredictor();
    if constexpr (kEnableVerification) {
        // Update all Predictors
        for (const auto& predictor : mPredictors) {
            predictor->add(timestampNs, pose, twist);
        }

        // Update Verifiers and calculate errors
        std::vector<float> error(std::size(mVerifiers));
        for (size_t i = 0; i < mLookaheadMs.size(); ++i) {
            constexpr float RADIAN_TO_DEGREES = 180 / M_PI;
            const int64_t atNs =
                    timestampNs + mLookaheadMs[i] * PosePredictorVerifier::kMillisToNanos;

            for (size_t j = 0; j < mPredictors.size(); ++j) {
                const size_t idx = i * std::size(mPredictors) + j;
                mVerifiers[idx].verifyActualPose(timestampNs, pose);
                mVerifiers[idx].addPredictedPose(atNs, mPredictors[j]->predict(atNs));
                error[idx] =  RADIAN_TO_DEGREES * mVerifiers[idx].lastError();
            }
        }
        // Record errors
        mPredictionRecorder.record(error);
        mPredictionDurableRecorder.record(error);
    } else /* constexpr */ {
        selectedPredictor->add(timestampNs, pose, twist);
    }

    // Deliver prediction
    const int64_t predictionTimeNs = timestampNs + (int64_t)predictionDurationNs;
    return selectedPredictor->predict(predictionTimeNs);
}

void PosePredictor::setPosePredictorType(PosePredictorType type) {
    if (!isValidPosePredictorType(type)) return;
    if (type == mSetType) return;
    mSetType = type;
    if (type == android::media::PosePredictorType::AUTO) {
        type = android::media::PosePredictorType::LEAST_SQUARES;
    }
    if (type != mCurrentType) {
        mCurrentType = type;
        if constexpr (!kEnableVerification) {
            // Verification keeps all predictors up-to-date.
            // If we don't enable verification, we must reset the current predictor.
            getCurrentPredictor()->reset();
        }
    }
}

std::string PosePredictor::toString(size_t index) const {
    std::string prefixSpace(index, ' ');
    std::string ss(prefixSpace);
    ss.append("PosePredictor:\n")
        .append(prefixSpace)
        .append(" Current Prediction Type: ")
        .append(android::media::toString(mCurrentType))
        .append("\n")
        .append(prefixSpace)
        .append(" Resets: ")
        .append(std::to_string(mResets))
        .append("\n")
        .append(getCurrentPredictor()->toString(index + 1));
    if constexpr (kEnableVerification) {
        // dump verification
        ss.append(prefixSpace)
            .append(" Prediction abs error (L1) degrees [ type (");
        for (size_t i = 0; i < mPredictors.size(); ++i) {
            if (i > 0) ss.append(" , ");
            ss.append(mPredictors[i]->name());
        }
        ss.append(" ) x ( ");
        for (size_t i = 0; i < mLookaheadMs.size(); ++i) {
            if (i > 0) ss.append(" : ");
            ss.append(std::to_string(mLookaheadMs[i]));
        }
        std::vector<float> cumulativeAverageErrors(std::size(mVerifiers));
        for (size_t i = 0; i < cumulativeAverageErrors.size(); ++i) {
            cumulativeAverageErrors[i] = mVerifiers[i].cumulativeAverageError();
        }
        ss.append(" ) ms ]\n")
            .append(prefixSpace)
            .append("  Cumulative Average Error:\n")
            .append(prefixSpace)
            .append("   ")
            .append(VectorRecorder::toString(cumulativeAverageErrors, mDelimiterIdx, "%.3g"))
            .append("\n")
            .append(prefixSpace)
            .append("  PerMinuteHistory:\n")
            .append(mPredictionDurableRecorder.toString(index + 3))
            .append(prefixSpace)
            .append("  PerSecondHistory:\n")
            .append(mPredictionRecorder.toString(index + 3));
    }
    return ss;
}

std::shared_ptr<PredictorBase> PosePredictor::getCurrentPredictor() const {
    // we don't use a map here, we look up directly
    switch (mCurrentType) {
    default:
    case android::media::PosePredictorType::LAST:
        return mPredictors[0];
    case android::media::PosePredictorType::TWIST:
        return mPredictors[1];
    case android::media::PosePredictorType::AUTO: // shouldn't occur here.
    case android::media::PosePredictorType::LEAST_SQUARES:
        return mPredictors[2];
    }
}

} // namespace android::media
