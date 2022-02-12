/*
 * Copyright (C) 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License"){}
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

#include "media/HeadTrackingProcessor.h"

#include "ModeSelector.h"
#include "PoseDriftCompensator.h"
#include "QuaternionUtil.h"
#include "ScreenHeadFusion.h"

namespace android {
namespace media {
namespace {

using Eigen::Quaternionf;
using Eigen::Vector3f;

class HeadTrackingProcessorImpl : public HeadTrackingProcessor {
  public:
    HeadTrackingProcessorImpl(const Options& options, HeadTrackingMode initialMode)
        : mOptions(options),
          mHeadPoseDriftCompensator(PoseDriftCompensator::Options{
                  .translationalDriftTimeConstant = options.translationalDriftTimeConstant,
                  .rotationalDriftTimeConstant = options.rotationalDriftTimeConstant,
          }),
          mScreenPoseDriftCompensator(PoseDriftCompensator::Options{
                  .translationalDriftTimeConstant = options.translationalDriftTimeConstant,
                  .rotationalDriftTimeConstant = options.rotationalDriftTimeConstant,
          }),
          mModeSelector(ModeSelector::Options{.freshnessTimeout = options.freshnessTimeout},
                        initialMode),
          mRateLimiter(PoseRateLimiter::Options{
                  .maxTranslationalVelocity = options.maxTranslationalVelocity,
                  .maxRotationalVelocity = options.maxRotationalVelocity}) {}

    void setDesiredMode(HeadTrackingMode mode) override { mModeSelector.setDesiredMode(mode); }

    void setWorldToHeadPose(int64_t timestamp, const Pose3f& worldToHead,
                            const Twist3f& headTwist) override {
        Pose3f predictedWorldToHead =
                worldToHead * integrate(headTwist, mOptions.predictionDuration);
        mHeadPoseDriftCompensator.setInput(timestamp, predictedWorldToHead);
        mWorldToHeadTimestamp = timestamp;
    }

    void setWorldToScreenPose(int64_t timestamp, const Pose3f& worldToScreen) override {
        if (mPhysicalToLogicalAngle != mPendingPhysicalToLogicalAngle) {
            // We're introducing an artificial discontinuity. Enable the rate limiter.
            mRateLimiter.enable();
            mPhysicalToLogicalAngle = mPendingPhysicalToLogicalAngle;
        }

        mScreenPoseDriftCompensator.setInput(
                timestamp, worldToScreen * Pose3f(rotateY(-mPhysicalToLogicalAngle)));
        mWorldToScreenTimestamp = timestamp;
    }

    void setScreenToStagePose(const Pose3f& screenToStage) override {
        mModeSelector.setScreenToStagePose(screenToStage);
    }

    void setDisplayOrientation(float physicalToLogicalAngle) override {
        mPendingPhysicalToLogicalAngle = physicalToLogicalAngle;
    }

    void calculate(int64_t timestamp) override {
        if (mWorldToHeadTimestamp.has_value()) {
            const Pose3f worldToHead = mHeadPoseDriftCompensator.getOutput();
            mScreenHeadFusion.setWorldToHeadPose(mWorldToHeadTimestamp.value(), worldToHead);
            mModeSelector.setWorldToHeadPose(mWorldToHeadTimestamp.value(), worldToHead);
        }

        if (mWorldToScreenTimestamp.has_value()) {
            const Pose3f worldToLogicalScreen = mScreenPoseDriftCompensator.getOutput();
            mScreenHeadFusion.setWorldToScreenPose(mWorldToScreenTimestamp.value(),
                                                   worldToLogicalScreen);
        }

        auto maybeScreenToHead = mScreenHeadFusion.calculate();
        if (maybeScreenToHead.has_value()) {
            mModeSelector.setScreenToHeadPose(maybeScreenToHead->timestamp,
                                              maybeScreenToHead->pose);
        } else {
            mModeSelector.setScreenToHeadPose(timestamp, std::nullopt);
        }

        HeadTrackingMode prevMode = mModeSelector.getActualMode();
        mModeSelector.calculate(timestamp);
        if (mModeSelector.getActualMode() != prevMode) {
            // Mode has changed, enable rate limiting.
            mRateLimiter.enable();
        }
        mRateLimiter.setTarget(mModeSelector.getHeadToStagePose());
        mHeadToStagePose = mRateLimiter.calculatePose(timestamp);
    }

    Pose3f getHeadToStagePose() const override { return mHeadToStagePose; }

    HeadTrackingMode getActualMode() const override { return mModeSelector.getActualMode(); }

    void recenter(bool recenterHead, bool recenterScreen) override {
        if (recenterHead) {
            mHeadPoseDriftCompensator.recenter();
        }
        if (recenterScreen) {
            mScreenPoseDriftCompensator.recenter();
        }

        // If a sensor being recentered is included in the current mode, apply rate limiting to
        // avoid discontinuities.
        HeadTrackingMode mode = mModeSelector.getActualMode();
        if ((recenterHead && (mode == HeadTrackingMode::WORLD_RELATIVE ||
                              mode == HeadTrackingMode::SCREEN_RELATIVE)) ||
            (recenterScreen && mode == HeadTrackingMode::SCREEN_RELATIVE)) {
            mRateLimiter.enable();
        }
    }

  private:
    const Options mOptions;
    float mPhysicalToLogicalAngle = 0;
    // We store the physical to logical angle as "pending" until the next world-to-screen sample it
    // applies to arrives.
    float mPendingPhysicalToLogicalAngle = 0;
    std::optional<int64_t> mWorldToHeadTimestamp;
    std::optional<int64_t> mWorldToScreenTimestamp;
    Pose3f mHeadToStagePose;
    PoseDriftCompensator mHeadPoseDriftCompensator;
    PoseDriftCompensator mScreenPoseDriftCompensator;
    ScreenHeadFusion mScreenHeadFusion;
    ModeSelector mModeSelector;
    PoseRateLimiter mRateLimiter;
};

}  // namespace

std::unique_ptr<HeadTrackingProcessor> createHeadTrackingProcessor(
        const HeadTrackingProcessor::Options& options, HeadTrackingMode initialMode) {
    return std::make_unique<HeadTrackingProcessorImpl>(options, initialMode);
}

}  // namespace media
}  // namespace android
