/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include <chrono>
#include <condition_variable>
#include <limits>
#include <memory>
#include <mutex>
#include <thread>

#include <media/HeadTrackingProcessor.h>
#include <media/SensorPoseProvider.h>
#include <media/VectorRecorder.h>

namespace android {

/**
 * This class encapsulates the logic for pose processing, intended for driving a spatializer effect.
 * This includes integration with the Sensor sub-system for retrieving sensor data, doing all the
 * necessary processing, etc.
 *
 * Calculations happen on a dedicated thread and published to the client via the Listener interface.
 * A calculation may be triggered in one of two ways:
 * - By calling calculateAsync() - calculation will be kicked off in the background.
 * - By setting a timeout in the ctor, a calculation will be triggered after the timeout elapsed
 *   from the last calculateAsync() call.
 *
 * This class is thread-safe.
 */
class SpatializerPoseController : private media::SensorPoseProvider::Listener {
  public:
    static constexpr int32_t INVALID_SENSOR = media::SensorPoseProvider::INVALID_HANDLE;

    /**
     * Listener interface for getting pose and mode updates.
     * Methods will always be invoked from a designated thread.
     */
    class Listener {
      public:
        virtual ~Listener() = default;

        virtual void onHeadToStagePose(const media::Pose3f&) = 0;
        virtual void onActualModeChange(media::HeadTrackingMode) = 0;
    };

    /**
     * Ctor.
     * sensorPeriod determines how often to receive updates from the sensors (input rate).
     * maxUpdatePeriod determines how often to produce an output when calculateAsync() isn't
     * invoked; passing nullopt means an output is never produced.
     */
    SpatializerPoseController(Listener* listener, std::chrono::microseconds sensorPeriod,
                               std::optional<std::chrono::microseconds> maxUpdatePeriod);

    /** Dtor. */
    ~SpatializerPoseController();

    /**
     * Set the sensor that is to be used for head-tracking.
     * INVALID_SENSOR can be used to disable head-tracking.
     */
    void setHeadSensor(int32_t sensor);

    /**
     * Set the sensor that is to be used for screen-tracking.
     * INVALID_SENSOR can be used to disable screen-tracking.
     */
    void setScreenSensor(int32_t sensor);

    /** Sets the desired head-tracking mode. */
    void setDesiredMode(media::HeadTrackingMode mode);

    /**
     * Set the screen-to-stage pose, used in all modes.
     */
    void setScreenToStagePose(const media::Pose3f& screenToStage);

    /**
     * Sets the display orientation.
     * Orientation is expressed in the angle of rotation from the physical "up" side of the screen
     * to the logical "up" side of the content displayed the screen. Counterclockwise angles, as
     * viewed while facing the screen are positive.
     */
    void setDisplayOrientation(float physicalToLogicalAngle);

    /**
     * This causes the current poses for both the head and screen to be considered "center".
     */
    void recenter();

    /**
     * This call triggers the recalculation of the output and the invocation of the relevant
     * callbacks. This call is async and the callbacks will be triggered shortly after.
     */
    void calculateAsync();

    /**
     * Blocks until calculation and invocation of the respective callbacks has happened at least
     * once. Do not call from within callbacks.
     */
    void waitUntilCalculated();

    // convert fields to a printable string
    std::string toString(unsigned level) const;

  private:
    mutable std::timed_mutex mMutex;
    Listener* const mListener;
    const std::chrono::microseconds mSensorPeriod;
    // Order matters for the following two members to ensure correct destruction.
    std::unique_ptr<media::HeadTrackingProcessor> mProcessor;
    std::unique_ptr<media::SensorPoseProvider> mPoseProvider;
    int32_t mHeadSensor = media::SensorPoseProvider::INVALID_HANDLE;
    int32_t mScreenSensor = media::SensorPoseProvider::INVALID_HANDLE;
    std::optional<media::HeadTrackingMode> mActualMode;
    std::condition_variable_any mCondVar;
    bool mShouldCalculate = true;
    bool mShouldExit = false;
    bool mCalculated = false;

    media::VectorRecorder mHeadSensorRecorder{
        8 /* vectorSize */, std::chrono::seconds(1), 10 /* maxLogLine */,
        { 3, 6, 7 } /* delimiterIdx */};
    media::VectorRecorder mHeadSensorDurableRecorder{
        8 /* vectorSize */, std::chrono::minutes(1), 10 /* maxLogLine */,
        { 3, 6, 7 } /* delimiterIdx */};

    media::VectorRecorder mScreenSensorRecorder{
        4 /* vectorSize */, std::chrono::seconds(1), 10 /* maxLogLine */,
        { 3 } /* delimiterIdx */};
    media::VectorRecorder mScreenSensorDurableRecorder{
        4 /* vectorSize */, std::chrono::minutes(1), 10 /* maxLogLine */,
        { 3 } /* delimiterIdx */};

    // It's important that mThread is the last variable in this class
    // since we starts mThread in initializer list
    std::thread mThread;

    void onPose(int64_t timestamp, int32_t sensor, const media::Pose3f& pose,
                const std::optional<media::Twist3f>& twist, bool isNewReference) override;

    /**
     * Calculates the new outputs and updates internal state. Must be called with the lock held.
     * Returns values that should be passed to the respective callbacks.
     */
    std::tuple<media::Pose3f, std::optional<media::HeadTrackingMode>> calculate_l();
};

}  // namespace android
