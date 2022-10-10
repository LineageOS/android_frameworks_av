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
#include <inttypes.h>

#include <android-base/stringprintf.h>
#include <audio_utils/SimpleLog.h>
#include "media/HeadTrackingProcessor.h"

#include "ModeSelector.h"
#include "PoseBias.h"
#include "QuaternionUtil.h"
#include "ScreenHeadFusion.h"
#include "StillnessDetector.h"

namespace android {
namespace media {
namespace {

using android::base::StringAppendF;
using Eigen::Quaternionf;
using Eigen::Vector3f;

class HeadTrackingProcessorImpl : public HeadTrackingProcessor {
  public:
    HeadTrackingProcessorImpl(const Options& options, HeadTrackingMode initialMode)
        : mOptions(options),
          mHeadStillnessDetector(StillnessDetector::Options{
                  .defaultValue = false,
                  .windowDuration = options.autoRecenterWindowDuration,
                  .translationalThreshold = options.autoRecenterTranslationalThreshold,
                  .rotationalThreshold = options.autoRecenterRotationalThreshold,
          }),
          mScreenStillnessDetector(StillnessDetector::Options{
                  .defaultValue = true,
                  .windowDuration = options.screenStillnessWindowDuration,
                  .translationalThreshold = options.screenStillnessTranslationalThreshold,
                  .rotationalThreshold = options.screenStillnessRotationalThreshold,
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
        mHeadPoseBias.setInput(predictedWorldToHead);
        mHeadStillnessDetector.setInput(timestamp, predictedWorldToHead);
        mWorldToHeadTimestamp = timestamp;
    }

    void setWorldToScreenPose(int64_t timestamp, const Pose3f& worldToScreen) override {
        if (mPhysicalToLogicalAngle != mPendingPhysicalToLogicalAngle) {
            // We're introducing an artificial discontinuity. Enable the rate limiter.
            mRateLimiter.enable();
            mPhysicalToLogicalAngle = mPendingPhysicalToLogicalAngle;
        }

        Pose3f worldToLogicalScreen = worldToScreen * Pose3f(rotateY(-mPhysicalToLogicalAngle));
        mScreenPoseBias.setInput(worldToLogicalScreen);
        mScreenStillnessDetector.setInput(timestamp, worldToLogicalScreen);
        mWorldToScreenTimestamp = timestamp;
    }

    void setScreenToStagePose(const Pose3f& screenToStage) override {
        mModeSelector.setScreenToStagePose(screenToStage);
    }

    void setDisplayOrientation(float physicalToLogicalAngle) override {
        mPendingPhysicalToLogicalAngle = physicalToLogicalAngle;
    }

    void calculate(int64_t timestamp) override {
        bool screenStable = true;

        // Handle the screen first, since it might: trigger a recentering of the head.
        if (mWorldToScreenTimestamp.has_value()) {
            const Pose3f worldToLogicalScreen = mScreenPoseBias.getOutput();
            screenStable = mScreenStillnessDetector.calculate(timestamp);
            mModeSelector.setScreenStable(mWorldToScreenTimestamp.value(), screenStable);
            // Whenever the screen is unstable, recenter the head pose.
            if (!screenStable) {
                recenter(true, false);
            }
            mScreenHeadFusion.setWorldToScreenPose(mWorldToScreenTimestamp.value(),
                                                   worldToLogicalScreen);
        }

        // Handle head.
        if (mWorldToHeadTimestamp.has_value()) {
            Pose3f worldToHead = mHeadPoseBias.getOutput();
            // Auto-recenter.
            bool headStable = mHeadStillnessDetector.calculate(timestamp);
            if (headStable || !screenStable) {
                recenter(true, false);
                worldToHead = mHeadPoseBias.getOutput();
            }

            mScreenHeadFusion.setWorldToHeadPose(mWorldToHeadTimestamp.value(), worldToHead);
            mModeSelector.setWorldToHeadPose(mWorldToHeadTimestamp.value(), worldToHead);
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
            mHeadPoseBias.recenter();
            mHeadStillnessDetector.reset();
            mLocalLog.log("recenter Head");
        }
        if (recenterScreen) {
            mScreenPoseBias.recenter();
            mScreenStillnessDetector.reset();
            mLocalLog.log("recenter Screen");
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

    std::string toString_l(unsigned level) const override {
        std::string prefixSpace(level, ' ');
        std::string ss = prefixSpace + "HeadTrackingProcessor:\n";
        StringAppendF(&ss, "%s maxTranslationalVelocity: %f meter/second\n", prefixSpace.c_str(),
                      mOptions.maxTranslationalVelocity);
        StringAppendF(&ss, "%s maxRotationalVelocity: %f rad/second\n", prefixSpace.c_str(),
                      mOptions.maxRotationalVelocity);
        StringAppendF(&ss, "%s freshnessTimeout: %0.4f ms\n", prefixSpace.c_str(),
                      media::nsToFloatMs(mOptions.freshnessTimeout));
        StringAppendF(&ss, "%s predictionDuration: %0.4f ms\n", prefixSpace.c_str(),
                      media::nsToFloatMs(mOptions.predictionDuration));
        StringAppendF(&ss, "%s autoRecenterWindowDuration: %0.4f ms\n", prefixSpace.c_str(),
                      media::nsToFloatMs(mOptions.autoRecenterWindowDuration));
        StringAppendF(&ss, "%s autoRecenterTranslationalThreshold: %f meter\n", prefixSpace.c_str(),
                      mOptions.autoRecenterTranslationalThreshold);
        StringAppendF(&ss, "%s autoRecenterRotationalThreshold: %f radians\n", prefixSpace.c_str(),
                      mOptions.autoRecenterRotationalThreshold);
        StringAppendF(&ss, "%s screenStillnessWindowDuration: %0.4f ms\n", prefixSpace.c_str(),
                      media::nsToFloatMs(mOptions.screenStillnessWindowDuration));
        StringAppendF(&ss, "%s screenStillnessTranslationalThreshold: %f meter\n",
                      prefixSpace.c_str(), mOptions.screenStillnessTranslationalThreshold);
        StringAppendF(&ss, "%s screenStillnessRotationalThreshold: %f radians\n",
                      prefixSpace.c_str(), mOptions.screenStillnessRotationalThreshold);
        ss += mModeSelector.toString(level + 1);
        ss += mRateLimiter.toString(level + 1);
        ss.append(prefixSpace + "ReCenterHistory:\n");
        ss += mLocalLog.dumpToString((prefixSpace + " ").c_str(), mMaxLocalLogLine);
        return ss;
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
    PoseBias mHeadPoseBias;
    PoseBias mScreenPoseBias;
    StillnessDetector mHeadStillnessDetector;
    StillnessDetector mScreenStillnessDetector;
    ScreenHeadFusion mScreenHeadFusion;
    ModeSelector mModeSelector;
    PoseRateLimiter mRateLimiter;
    static constexpr std::size_t mMaxLocalLogLine = 10;
    SimpleLog mLocalLog{mMaxLocalLogLine};
};

}  // namespace

std::unique_ptr<HeadTrackingProcessor> createHeadTrackingProcessor(
        const HeadTrackingProcessor::Options& options, HeadTrackingMode initialMode) {
    return std::make_unique<HeadTrackingProcessorImpl>(options, initialMode);
}

std::string toString(HeadTrackingMode mode) {
    switch (mode) {
        case HeadTrackingMode::STATIC:
            return "STATIC";
        case HeadTrackingMode::WORLD_RELATIVE:
            return "WORLD_RELATIVE";
        case HeadTrackingMode::SCREEN_RELATIVE:
            return "SCREEN_RELATIVE";
    }
    return "EnumNotImplemented";
};

}  // namespace media
}  // namespace android
