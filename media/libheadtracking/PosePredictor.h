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

#include "PosePredictorVerifier.h"
#include <memory>
#include <audio_utils/Statistics.h>
#include <media/PosePredictorType.h>
#include <media/Twist.h>
#include <media/VectorRecorder.h>

namespace android::media {

// Interface for generic pose predictors
class PredictorBase {
public:
    virtual ~PredictorBase() = default;
    virtual void add(int64_t atNs, const Pose3f& pose, const Twist3f& twist) = 0;
    virtual Pose3f predict(int64_t atNs) const = 0;
    virtual void reset() = 0;
    virtual std::string name() const = 0;
    virtual std::string toString(size_t index) const = 0;
};

/**
 * LastPredictor uses the last sample Pose for prediction
 *
 * This class is not thread-safe.
 */
class LastPredictor : public PredictorBase {
public:
    void add(int64_t atNs, const Pose3f& pose, const Twist3f& twist) override {
        (void)atNs;
        (void)twist;
        mLastPose = pose;
    }

    Pose3f predict(int64_t atNs) const override {
        (void)atNs;
        return mLastPose;
    }

    void reset() override {
        mLastPose = {};
    }

    std::string name() const override {
        return "LAST";
    }

    std::string toString(size_t index) const override {
        std::string s(index, ' ');
        s.append("LastPredictor using last pose: ")
            .append(mLastPose.toString())
            .append("\n");
        return s;
    }

private:
    Pose3f mLastPose;
};

/**
 * TwistPredictor uses the last sample Twist and Pose for prediction
 *
 * This class is not thread-safe.
 */
class TwistPredictor : public PredictorBase {
public:
    void add(int64_t atNs, const Pose3f& pose, const Twist3f& twist) override {
        mLastAtNs = atNs;
        mLastPose = pose;
        mLastTwist = twist;
    }

    Pose3f predict(int64_t atNs) const override {
        return mLastPose * integrate(mLastTwist, atNs - mLastAtNs);
    }

    void reset() override {
        mLastAtNs = {};
        mLastPose = {};
        mLastTwist = {};
    }

    std::string name() const override {
        return "TWIST";
    }

    std::string toString(size_t index) const override {
        std::string s(index, ' ');
        s.append("TwistPredictor using last pose: ")
            .append(mLastPose.toString())
            .append(" last twist: ")
            .append(mLastTwist.toString())
            .append("\n");
        return s;
    }

private:
    int64_t mLastAtNs{};
    Pose3f mLastPose;
    Twist3f mLastTwist;
};


/**
 * LeastSquaresPredictor uses the Pose history for prediction.
 *
 * A exponential weighted least squares is used.
 *
 * This class is not thread-safe.
 */
class LeastSquaresPredictor : public PredictorBase {
public:
    // alpha is the exponential decay.
    LeastSquaresPredictor(double alpha = kDefaultAlphaEstimator)
        : mAlpha(alpha)
        , mRw(alpha)
        , mRx(alpha)
        , mRy(alpha)
        , mRz(alpha)
        {}

    void add(int64_t atNs, const Pose3f& pose, const Twist3f& twist) override;
    Pose3f predict(int64_t atNs) const override;
    void reset() override;
    std::string name() const override {
        return "LEAST_SQUARES(" + std::to_string(mAlpha) + ")";
    }
    std::string toString(size_t index) const override;

private:
    const double mAlpha;
    int64_t mLastAtNs{};
    Pose3f mLastPose;
    static constexpr double kDefaultAlphaEstimator = 0.2;
    static constexpr size_t kMinimumSamplesForPrediction = 4;
    audio_utils::LinearLeastSquaresFit<double> mRw;
    audio_utils::LinearLeastSquaresFit<double> mRx;
    audio_utils::LinearLeastSquaresFit<double> mRy;
    audio_utils::LinearLeastSquaresFit<double> mRz;
};

/*
 * PosePredictor predicts the pose given sensor input at a time in the future.
 *
 * This class is not thread safe.
 */
class PosePredictor {
public:
    PosePredictor();

    Pose3f predict(int64_t timestampNs, const Pose3f& pose, const Twist3f& twist,
            float predictionDurationNs);

    void setPosePredictorType(PosePredictorType type);

    // convert predictions to a printable string
    std::string toString(size_t index) const;

private:
    static constexpr int64_t kMaximumSampleIntervalBeforeResetNs =
            300'000'000;

    // Predictors
    const std::vector<std::shared_ptr<PredictorBase>> mPredictors;

    // Verifiers, create one for an array of future lookaheads for comparison.
    const std::vector<int> mLookaheadMs;

    std::vector<PosePredictorVerifier> mVerifiers;

    const std::vector<size_t> mDelimiterIdx;

    // Recorders
    media::VectorRecorder mPredictionRecorder{
        std::size(mVerifiers) /* vectorSize */, std::chrono::seconds(1), 10 /* maxLogLine */,
        mDelimiterIdx};
    media::VectorRecorder mPredictionDurableRecorder{
        std::size(mVerifiers) /* vectorSize */, std::chrono::minutes(1), 10 /* maxLogLine */,
        mDelimiterIdx};

    // Status

    // SetType is the externally set predictor type.  It may include AUTO.
    PosePredictorType mSetType = PosePredictorType::LEAST_SQUARES;

    // CurrentType is the actual predictor type used by this class.
    // It does not include AUTO because that metatype means the class
    // chooses the best predictor type based on sensor statistics.
    PosePredictorType mCurrentType = PosePredictorType::LEAST_SQUARES;

    int64_t mResets{};
    int64_t mLastTimestampNs{};

    // Returns current predictor
    std::shared_ptr<PredictorBase> getCurrentPredictor() const;
};

}  // namespace android::media
