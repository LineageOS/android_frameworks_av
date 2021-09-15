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

#include <media/SensorPoseProvider.h>

#define LOG_TAG "SensorPoseProvider"

#include <inttypes.h>

#include <future>
#include <map>
#include <thread>

#include <android/looper.h>
#include <log/log_main.h>

#include "QuaternionUtil.h"

namespace android {
namespace media {
namespace {

/**
 * RAII-wrapper around ASensorEventQueue, which destroys it on destruction.
 */
class EventQueueGuard {
  public:
    EventQueueGuard(ASensorManager* manager, ASensorEventQueue* queue)
        : mManager(manager), mQueue(queue) {}

    ~EventQueueGuard() {
        if (mQueue) {
            int ret = ASensorManager_destroyEventQueue(mManager, mQueue);
            if (ret) {
                ALOGE("Failed to destroy event queue: %s\n", strerror(ret));
            }
        }
    }

    EventQueueGuard(const EventQueueGuard&) = delete;
    EventQueueGuard& operator=(const EventQueueGuard&) = delete;

    [[nodiscard]] ASensorEventQueue* get() const { return mQueue; }

  private:
    ASensorManager* const mManager;
    ASensorEventQueue* mQueue;
};

/**
 * RAII-wrapper around an enabled sensor, which disables it upon destruction.
 */
class SensorEnableGuard {
  public:
    SensorEnableGuard(ASensorEventQueue* queue, const ASensor* sensor)
        : mQueue(queue), mSensor(sensor) {}

    ~SensorEnableGuard() {
        if (mSensor) {
            int ret = ASensorEventQueue_disableSensor(mQueue, mSensor);
            if (ret) {
                ALOGE("Failed to disable sensor: %s\n", strerror(ret));
            }
        }
    }

    SensorEnableGuard(const SensorEnableGuard&) = delete;
    SensorEnableGuard& operator=(const SensorEnableGuard&) = delete;

    // Enable moving.
    SensorEnableGuard(SensorEnableGuard&& other) : mQueue(other.mQueue), mSensor(other.mSensor) {
        other.mSensor = nullptr;
    }

  private:
    ASensorEventQueue* const mQueue;
    const ASensor* mSensor;
};

/**
 * Streams the required events to a PoseListener, based on events originating from the Sensor stack.
 */
class SensorPoseProviderImpl : public SensorPoseProvider {
  public:
    static std::unique_ptr<SensorPoseProvider> create(const char* packageName, Listener* listener) {
        std::unique_ptr<SensorPoseProviderImpl> result(
                new SensorPoseProviderImpl(packageName, listener));
        return result->waitInitFinished() ? std::move(result) : nullptr;
    }

    ~SensorPoseProviderImpl() override {
        // Disable all active sensors.
        mEnabledSensors.clear();
        ALooper_wake(mLooper);
        mThread.join();
    }

    int32_t startSensor(const ASensor* sensor, std::chrono::microseconds samplingPeriod) override {
        int32_t handle = ASensor_getHandle(sensor);

        // Enable the sensor.
        if (ASensorEventQueue_registerSensor(mQueue, sensor, samplingPeriod.count(), 0)) {
            ALOGE("Failed to enable sensor");
            return INVALID_HANDLE;
        }

        mEnabledSensors.emplace(handle, SensorEnableGuard(mQueue, sensor));
        return handle;
    }

    void stopSensor(int handle) override { mEnabledSensors.erase(handle); }

  private:
    ALooper* mLooper;
    Listener* const mListener;

    std::thread mThread;
    std::map<int32_t, SensorEnableGuard> mEnabledSensors;
    ASensorEventQueue* mQueue;

    // We must do some of the initialization operations on the worker thread, because the API relies
    // on the thread-local looper. In addition, as a matter of convenience, we store some of the
    // state on the stack.
    // For that reason, we use a two-step initialization approach, where the ctor mostly just starts
    // the worker thread and that thread would notify, via the promise below whenever initialization
    // is finished, and whether it was successful.
    std::promise<bool> mInitPromise;

    SensorPoseProviderImpl(const char* packageName, Listener* listener)
        : mListener(listener),
          mThread([this, p = std::string(packageName)] { threadFunc(p.c_str()); }) {}

    void initFinished(bool success) { mInitPromise.set_value(success); }

    bool waitInitFinished() { return mInitPromise.get_future().get(); }

    void threadFunc(const char* packageName) {
        // Obtain looper.
        mLooper = ALooper_prepare(ALOOPER_PREPARE_ALLOW_NON_CALLBACKS);

        // The number 19 is arbitrary, only useful if using multiple objects on the same looper.
        constexpr int kIdent = 19;

        // Obtain sensor manager.
        ASensorManager* sensor_manager = ASensorManager_getInstanceForPackage(packageName);
        if (!sensor_manager) {
            ALOGE("Failed to get a sensor manager");
            initFinished(false);
            return;
        }

        // Create event queue.
        mQueue = ASensorManager_createEventQueue(sensor_manager, mLooper, kIdent, nullptr, nullptr);

        if (mQueue == nullptr) {
            ALOGE("Failed to create a sensor event queue");
            initFinished(false);
            return;
        }

        EventQueueGuard eventQueueGuard(sensor_manager, mQueue);

        initFinished(true);

        while (true) {
            int ret = ALooper_pollOnce(-1 /* no timeout */, nullptr, nullptr, nullptr);

            switch (ret) {
                case ALOOPER_POLL_WAKE:
                    // Normal way to exit.
                    return;

                case kIdent:
                    // Possible events on our queue.
                    break;

                default:
                    ALOGE("Unexpected status out of ALooper_pollOnce: %d", ret);
            }

            // Process an event.
            ASensorEvent event;
            ssize_t size = ASensorEventQueue_getEvents(mQueue, &event, 1);
            if (size < 0 || size > 1) {
                ALOGE("Unexpected return value from ASensorEventQueue_getEvents: %zd", size);
                break;
            }
            if (size == 0) {
                // No events.
                continue;
            }

            handleEvent(event);
        }
    }

    void handleEvent(const ASensorEvent& event) {
        auto value = parseEvent(event);
        mListener->onPose(event.timestamp, event.sensor, std::get<0>(value), std::get<1>(value));
    }

    static std::tuple<Pose3f, std::optional<Twist3f>> parseEvent(const ASensorEvent& event) {
        // TODO(ytai): Add more types.
        switch (event.type) {
            case ASENSOR_TYPE_ROTATION_VECTOR:
            case ASENSOR_TYPE_GAME_ROTATION_VECTOR: {
                Eigen::Quaternionf quat(event.data[3], event.data[0], event.data[1], event.data[2]);
                // Adapt to different frame convention.
                quat *= rotateX(-M_PI_2);
                return std::make_tuple(Pose3f(quat), std::optional<Twist3f>());
            }

            default:
                ALOGE("Unsupported sensor type: %" PRId32, event.type);
                return std::make_tuple(Pose3f(), std::optional<Twist3f>());
        }
    }
};

}  // namespace

std::unique_ptr<SensorPoseProvider> SensorPoseProvider::create(const char* packageName,
                                                               Listener* listener) {
    return SensorPoseProviderImpl::create(packageName, listener);
}

}  // namespace media
}  // namespace android
