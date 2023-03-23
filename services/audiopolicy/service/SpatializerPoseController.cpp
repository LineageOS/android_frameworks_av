/*
 * Copyright 2021, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "SpatializerPoseController.h"
#include <android-base/stringprintf.h>
#include <chrono>
#include <cstdint>
#include <string>

#define LOG_TAG "SpatializerPoseController"
//#define LOG_NDEBUG 0
#include <cutils/properties.h>
#include <sensor/Sensor.h>
#include <media/MediaMetricsItem.h>
#include <media/QuaternionUtil.h>
#include <utils/Log.h>
#include <utils/SystemClock.h>

namespace android {

using media::createHeadTrackingProcessor;
using media::HeadTrackingMode;
using media::HeadTrackingProcessor;
using media::Pose3f;
using media::SensorPoseProvider;
using media::Twist3f;

using namespace std::chrono_literals;

namespace {

// This is how fast, in m/s, we allow position to shift during rate-limiting.
constexpr float kMaxTranslationalVelocity = 2;

// This is how fast, in rad/s, we allow rotation angle to shift during rate-limiting.
constexpr float kMaxRotationalVelocity = 0.8f;

// This is how far into the future we predict the head pose.
// The prediction duration should be based on the actual latency from
// head-tracker to audio output, though setting the prediction duration too
// high may result in higher prediction errors when the head accelerates or
// decelerates (changes velocity).
//
// The head tracking predictor will do a best effort to achieve the requested
// prediction duration.  If the duration is too far in the future based on
// current sensor variance, the predictor may internally restrict duration to what
// is achievable with reasonable confidence as the "best prediction".
constexpr auto kPredictionDuration = 120ms;

// After not getting a pose sample for this long, we would treat the measurement as stale.
// The max connection interval is 50ms, and HT sensor event interval can differ depending on the
// sampling rate, scheduling, sensor eventQ FIFO etc. 120 (2 * 50 + 20) ms seems reasonable for now.
constexpr auto kFreshnessTimeout = 120ms;

// Auto-recenter kicks in after the head has been still for this long.
constexpr auto kAutoRecenterWindowDuration = 6s;

// Auto-recenter considers head not still if translated by this much (in meters, approx).
constexpr float kAutoRecenterTranslationThreshold = 0.1f;

// Auto-recenter considers head not still if rotated by this much (in radians, approx).
constexpr float kAutoRecenterRotationThreshold = 10.5f / 180 * M_PI;

// Screen is considered to be unstable (not still) if it has moved significantly within the last
// time window of this duration.
constexpr auto kScreenStillnessWindowDuration = 750ms;

// Screen is considered to have moved significantly if translated by this much (in meter, approx).
constexpr float kScreenStillnessTranslationThreshold = 0.1f;

// Screen is considered to have moved significantly if rotated by this much (in radians, approx).
constexpr float kScreenStillnessRotationThreshold = 15.0f / 180 * M_PI;

// Time units for system clock ticks. This is what the Sensor Framework timestamps represent and
// what we use for pose filtering.
using Ticks = std::chrono::nanoseconds;

// How many ticks in a second.
constexpr auto kTicksPerSecond = Ticks::period::den;

std::string getSensorMetricsId(int32_t sensorId) {
    return std::string(AMEDIAMETRICS_KEY_PREFIX_AUDIO_SENSOR).append(std::to_string(sensorId));
}

}  // namespace

SpatializerPoseController::SpatializerPoseController(Listener* listener,
                                        std::chrono::microseconds sensorPeriod,
                                        std::optional<std::chrono::microseconds> maxUpdatePeriod)
    : mListener(listener),
      mSensorPeriod(sensorPeriod),
      mProcessor(createHeadTrackingProcessor(HeadTrackingProcessor::Options{
              .maxTranslationalVelocity = kMaxTranslationalVelocity / kTicksPerSecond,
              .maxRotationalVelocity = kMaxRotationalVelocity / kTicksPerSecond,
              .freshnessTimeout = Ticks(kFreshnessTimeout).count(),
              .predictionDuration = []() -> float {
                  const int duration_ms =
                          property_get_int32("audio.spatializer.prediction_duration_ms", -1);
                  if (duration_ms >= 0) {
                      return duration_ms * 1'000'000LL;
                  } else {
                      return Ticks(kPredictionDuration).count();
                  }
              }(),
              .autoRecenterWindowDuration = Ticks(kAutoRecenterWindowDuration).count(),
              .autoRecenterTranslationalThreshold = kAutoRecenterTranslationThreshold,
              .autoRecenterRotationalThreshold = kAutoRecenterRotationThreshold,
              .screenStillnessWindowDuration = Ticks(kScreenStillnessWindowDuration).count(),
              .screenStillnessTranslationalThreshold = kScreenStillnessTranslationThreshold,
              .screenStillnessRotationalThreshold = kScreenStillnessRotationThreshold,
      })),
      mPoseProvider(SensorPoseProvider::create("headtracker", this)),
      mThread([this, maxUpdatePeriod] { // It's important that mThread is initialized after
                                        // everything else because it runs a member
                                        // function that may use any member
                                        // of this class.
          while (true) {
              Pose3f headToStage;
              std::optional<HeadTrackingMode> modeIfChanged;
              {
                  std::unique_lock lock(mMutex);
                  if (maxUpdatePeriod.has_value()) {
                      mCondVar.wait_for(lock, maxUpdatePeriod.value(),
                                        [this] { return mShouldExit || mShouldCalculate; });
                  } else {
                      mCondVar.wait(lock, [this] { return mShouldExit || mShouldCalculate; });
                  }
                  if (mShouldExit) {
                      ALOGV("Exiting thread");
                      return;
                  }

                  // Calculate.
                  std::tie(headToStage, modeIfChanged) = calculate_l();
              }

              // Invoke the callbacks outside the lock.
              mListener->onHeadToStagePose(headToStage);
              if (modeIfChanged) {
                  mListener->onActualModeChange(modeIfChanged.value());
              }

              {
                  std::lock_guard lock(mMutex);
                  if (!mCalculated) {
                      mCalculated = true;
                      mCondVar.notify_all();
                  }
                  mShouldCalculate = false;
              }
          }
      }) {
          const media::PosePredictorType posePredictorType =
                  (media::PosePredictorType)
                  property_get_int32("audio.spatializer.pose_predictor_type", -1);
          if (isValidPosePredictorType(posePredictorType)) {
              mProcessor->setPosePredictorType(posePredictorType);
          }
      }

SpatializerPoseController::~SpatializerPoseController() {
    {
        std::unique_lock lock(mMutex);
        mShouldExit = true;
        mCondVar.notify_all();
    }
    mThread.join();
}

void SpatializerPoseController::setHeadSensor(int32_t sensor) {
    std::lock_guard lock(mMutex);
    if (sensor == mHeadSensor) return;
    ALOGV("%s: new sensor:%d  mHeadSensor:%d  mScreenSensor:%d",
            __func__, sensor, mHeadSensor, mScreenSensor);

    // Stop current sensor, if valid and different from the other sensor.
    if (mHeadSensor != INVALID_SENSOR && mHeadSensor != mScreenSensor) {
        mPoseProvider->stopSensor(mHeadSensor);
        mediametrics::LogItem(getSensorMetricsId(mHeadSensor))
            .set(AMEDIAMETRICS_PROP_EVENT, AMEDIAMETRICS_PROP_EVENT_VALUE_STOP)
            .record();
    }

    if (sensor != INVALID_SENSOR) {
        if (sensor != mScreenSensor) {
            // Start new sensor.
            mHeadSensor =
                    mPoseProvider->startSensor(sensor, mSensorPeriod) ? sensor : INVALID_SENSOR;
            if (mHeadSensor != INVALID_SENSOR) {
                auto sensor = mPoseProvider->getSensorByHandle(mHeadSensor);
                std::string stringType = sensor ? sensor->getStringType().c_str() : "";
                mediametrics::LogItem(getSensorMetricsId(mHeadSensor))
                    .set(AMEDIAMETRICS_PROP_EVENT, AMEDIAMETRICS_PROP_EVENT_VALUE_START)
                    .set(AMEDIAMETRICS_PROP_MODE, AMEDIAMETRICS_PROP_MODE_VALUE_HEAD)
                    .set(AMEDIAMETRICS_PROP_TYPE, stringType)
                    .record();
            }
        } else {
            // Sensor is already enabled.
            mHeadSensor = mScreenSensor;
        }
    } else {
        mHeadSensor = INVALID_SENSOR;
    }

    mProcessor->recenter(true /* recenterHead */, false /* recenterScreen */, __func__);
}

void SpatializerPoseController::setScreenSensor(int32_t sensor) {
    std::lock_guard lock(mMutex);
    if (sensor == mScreenSensor) return;
    ALOGV("%s: new sensor:%d  mHeadSensor:%d  mScreenSensor:%d",
            __func__, sensor, mHeadSensor, mScreenSensor);

    // Stop current sensor, if valid and different from the other sensor.
    if (mScreenSensor != INVALID_SENSOR && mScreenSensor != mHeadSensor) {
        mPoseProvider->stopSensor(mScreenSensor);
        mediametrics::LogItem(getSensorMetricsId(mScreenSensor))
            .set(AMEDIAMETRICS_PROP_EVENT, AMEDIAMETRICS_PROP_EVENT_VALUE_STOP)
            .record();
    }

    if (sensor != INVALID_SENSOR) {
        if (sensor != mHeadSensor) {
            // Start new sensor.
            mScreenSensor =
                    mPoseProvider->startSensor(sensor, mSensorPeriod) ? sensor : INVALID_SENSOR;
            auto sensor = mPoseProvider->getSensorByHandle(mScreenSensor);
            std::string stringType = sensor ? sensor->getStringType().c_str() : "";
            mediametrics::LogItem(getSensorMetricsId(mScreenSensor))
                .set(AMEDIAMETRICS_PROP_EVENT, AMEDIAMETRICS_PROP_EVENT_VALUE_START)
                .set(AMEDIAMETRICS_PROP_MODE, AMEDIAMETRICS_PROP_MODE_VALUE_SCREEN)
                .set(AMEDIAMETRICS_PROP_TYPE, stringType)
                .record();
        } else {
            // Sensor is already enabled.
            mScreenSensor = mHeadSensor;
        }
    } else {
        mScreenSensor = INVALID_SENSOR;
    }

    mProcessor->recenter(false /* recenterHead */, true /* recenterScreen */, __func__);
}

void SpatializerPoseController::setDesiredMode(HeadTrackingMode mode) {
    std::lock_guard lock(mMutex);
    mProcessor->setDesiredMode(mode);
}

void SpatializerPoseController::setScreenToStagePose(const Pose3f& screenToStage) {
    std::lock_guard lock(mMutex);
    mProcessor->setScreenToStagePose(screenToStage);
}

void SpatializerPoseController::setDisplayOrientation(float physicalToLogicalAngle) {
    std::lock_guard lock(mMutex);
    mProcessor->setDisplayOrientation(physicalToLogicalAngle);
}

void SpatializerPoseController::calculateAsync() {
    std::lock_guard lock(mMutex);
    mShouldCalculate = true;
    mCondVar.notify_all();
}

void SpatializerPoseController::waitUntilCalculated() {
    std::unique_lock lock(mMutex);
    mCondVar.wait(lock, [this] { return mCalculated; });
}

std::tuple<media::Pose3f, std::optional<media::HeadTrackingMode>>
SpatializerPoseController::calculate_l() {
    Pose3f headToStage;
    HeadTrackingMode mode;
    std::optional<media::HeadTrackingMode> modeIfChanged;

    mProcessor->calculate(elapsedRealtimeNano());
    headToStage = mProcessor->getHeadToStagePose();
    mode = mProcessor->getActualMode();
    if (!mActualMode.has_value() || mActualMode.value() != mode) {
        mActualMode = mode;
        modeIfChanged = mode;
    }
    return std::make_tuple(headToStage, modeIfChanged);
}

void SpatializerPoseController::recenter() {
    std::lock_guard lock(mMutex);
    mProcessor->recenter(true /* recenterHead */, true /* recenterScreen */, __func__);
}

void SpatializerPoseController::onPose(int64_t timestamp, int32_t sensor, const Pose3f& pose,
                                       const std::optional<Twist3f>& twist, bool isNewReference) {
    std::lock_guard lock(mMutex);
    constexpr float NANOS_TO_MILLIS = 1e-6;
    constexpr float RAD_TO_DEGREE = 180.f / M_PI;

    const float delayMs = (elapsedRealtimeNano() - timestamp) * NANOS_TO_MILLIS; // CLOCK_BOOTTIME

    if (sensor == mHeadSensor) {
        std::vector<float> pryprydt(8);  // pitch, roll, yaw, d_pitch, d_roll, d_yaw,
                                         // discontinuity, timestamp_delay
        media::quaternionToAngles(pose.rotation(), &pryprydt[0], &pryprydt[1], &pryprydt[2]);
        if (twist) {
            const auto rotationalVelocity = twist->rotationalVelocity();
            // The rotational velocity is an intrinsic transform (i.e. based on the head
            // coordinate system, not the world coordinate system).  It is a 3 element vector:
            // axis (d theta / dt).
            //
            // We leave rotational velocity relative to the head coordinate system,
            // as the initial head tracking sensor's world frame is arbitrary.
            media::quaternionToAngles(media::rotationVectorToQuaternion(rotationalVelocity),
                    &pryprydt[3], &pryprydt[4], &pryprydt[5]);
        }
        pryprydt[6] = isNewReference;
        pryprydt[7] = delayMs;
        for (size_t i = 0; i < 6; ++i) {
            // pitch, roll, yaw in degrees, referenced in degrees on the world frame.
            // d_pitch, d_roll, d_yaw rotational velocity in degrees/s, based on the world frame.
            pryprydt[i] *= RAD_TO_DEGREE;
        }
        mHeadSensorRecorder.record(pryprydt);
        mHeadSensorDurableRecorder.record(pryprydt);

        mProcessor->setWorldToHeadPose(timestamp, pose,
                                       twist.value_or(Twist3f()) / kTicksPerSecond);
        if (isNewReference) {
            mProcessor->recenter(true, false, __func__);
        }
    }
    if (sensor == mScreenSensor) {
        std::vector<float> pryt{ 0.f, 0.f, 0.f, delayMs}; // pitch, roll, yaw, timestamp_delay
        media::quaternionToAngles(pose.rotation(), &pryt[0], &pryt[1], &pryt[2]);
        for (size_t i = 0; i < 3; ++i) {
            pryt[i] *= RAD_TO_DEGREE;
        }
        mScreenSensorRecorder.record(pryt);
        mScreenSensorDurableRecorder.record(pryt);

        mProcessor->setWorldToScreenPose(timestamp, pose);
        if (isNewReference) {
            mProcessor->recenter(false, true, __func__);
        }
    }
}

std::string SpatializerPoseController::toString(unsigned level) const {
    std::string prefixSpace(level, ' ');
    std::string ss = prefixSpace + "SpatializerPoseController:\n";
    bool needUnlock = false;

    prefixSpace += ' ';
    auto now = std::chrono::steady_clock::now();
    if (!mMutex.try_lock_until(now + media::kSpatializerDumpSysTimeOutInSecond)) {
        ss.append(prefixSpace).append("try_lock failed, dumpsys maybe INACCURATE!\n");
    } else {
        needUnlock = true;
    }

    ss += prefixSpace;
    if (mHeadSensor == INVALID_SENSOR) {
        ss += "HeadSensor: INVALID\n";
    } else {
        base::StringAppendF(&ss, "HeadSensor: 0x%08x "
            "(active world-to-head : head-relative velocity) "
            "[ pitch, roll, yaw : d_pitch, d_roll, d_yaw : disc : delay ] "
            "(degrees, degrees/s, bool, ms)\n", mHeadSensor);
        ss.append(prefixSpace)
            .append(" PerMinuteHistory:\n")
            .append(mHeadSensorDurableRecorder.toString(level + 3))
            .append(prefixSpace)
            .append(" PerSecondHistory:\n")
            .append(mHeadSensorRecorder.toString(level + 3));
    }

    ss += prefixSpace;
    if (mScreenSensor == INVALID_SENSOR) {
        ss += "ScreenSensor: INVALID\n";
    } else {
        base::StringAppendF(&ss, "ScreenSensor: 0x%08x (active world-to-screen) "
            "[ pitch, roll, yaw : delay ] "
            "(degrees, ms)\n", mScreenSensor);
        ss.append(prefixSpace)
            .append(" PerMinuteHistory:\n")
            .append(mScreenSensorDurableRecorder.toString(level + 3))
            .append(prefixSpace)
            .append(" PerSecondHistory:\n")
            .append(mScreenSensorRecorder.toString(level + 3));
    }

    ss += prefixSpace;
    if (mActualMode.has_value()) {
        base::StringAppendF(&ss, "ActualMode: %s\n", media::toString(mActualMode.value()).c_str());
    } else {
        ss += "ActualMode NOTEXIST\n";
    }

    if (mProcessor) {
        ss += mProcessor->toString_l(level + 1);
    } else {
        ss.append(prefixSpace.c_str()).append("HeadTrackingProcessor not exist\n");
    }

    if (mPoseProvider) {
        ss += mPoseProvider->toString(level + 1);
    } else {
        ss.append(prefixSpace.c_str()).append("SensorPoseProvider not exist\n");
    }

    if (needUnlock) {
        mMutex.unlock();
    }
    // TODO: 233092747 add history sensor info with SimpleLog.
    return ss;
}

}  // namespace android
