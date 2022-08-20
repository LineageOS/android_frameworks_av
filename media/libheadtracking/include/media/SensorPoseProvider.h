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
#include <memory>
#include <optional>

#include <android/sensor.h>
#include <sensor/Sensor.h>

#include "Pose.h"
#include "Twist.h"

namespace android {
namespace media {

// Timeout for Spatializer dumpsys trylock, don't block for more than 3 seconds.
constexpr auto kSpatializerDumpSysTimeOutInSecond = std::chrono::seconds(3);

/**
 * A utility providing streaming of pose data from motion sensors provided by the Sensor Framework.
 *
 * A live instance of this interface keeps around some resources required for accessing sensor
 * readings (e.g. a thread and a queue). Those would be released when the instance is deleted.
 *
 * Once alive, individual sensors can be subscribed to using startSensor() and updates can be
 * stopped via stopSensor(). Those two methods should not be called concurrently and correct usage
 * is assumed.
 */
class SensorPoseProvider {
  public:
    static constexpr int32_t INVALID_HANDLE = ASENSOR_INVALID;

    /**
     * Interface for consuming pose-related sensor events.
     *
     * The listener will be provided with a stream of events, each including:
     * - A handle of the sensor responsible for the event.
     * - Timestamp.
     * - Pose.
     * - Optional twist (time-derivative of pose).
     *
     * Sensors having only orientation data will have the translation part of the pose set to
     * identity.
     *
     * Events are delivered in a serialized manner (i.e. callbacks do not need to be reentrant).
     * Callbacks should not block.
     */
    class Listener {
      public:
        virtual ~Listener() = default;

        virtual void onPose(int64_t timestamp, int32_t handle, const Pose3f& pose,
                            const std::optional<Twist3f>& twist, bool isNewReference) = 0;
    };

    /**
     * Creates a new SensorPoseProvider instance.
     * Events will be delivered to the listener as long as the returned instance is kept alive.
     * @param packageName Client's package name.
     * @param listener The listener that will get the events.
     * @return The new instance, or nullptr in case of failure.
     */
    static std::unique_ptr<SensorPoseProvider> create(const char* packageName, Listener* listener);

    virtual ~SensorPoseProvider() = default;

    /**
     * Start receiving pose updates from a given sensor.
     * Attempting to start a sensor that has already been started results in undefined behavior.
     * @param sensor The sensor to subscribe to.
     * @param samplingPeriod Sampling interval, in microseconds. Actual rate might be slightly
     * different.
     * @return true iff succeeded.
     */
    virtual bool startSensor(int32_t sensor, std::chrono::microseconds samplingPeriod) = 0;

    /**
     * Stop a sensor, previously started with startSensor(). It is not required to stop all sensors
     * before deleting the SensorPoseProvider instance.
     * @param handle The sensor handle, as provided to startSensor().
     */
    virtual void stopSensor(int32_t handle) = 0;

    /**
     * Returns the sensor or nullopt if it does not exist.
     *
     * The Sensor object has const methods that can be used to
     * discover properties of the sensor.
     */
    virtual std::optional<const Sensor> getSensorByHandle(int32_t handle) = 0;

    /**
     * Dump SensorPoseProvider parameters and history data.
     */
    virtual std::string toString(unsigned level) = 0;
};

}  // namespace media
}  // namespace android
