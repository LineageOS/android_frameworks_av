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

#include <android-base/thread_annotations.h>
#include <log/log_main.h>
#include <sensor/Sensor.h>
#include <sensor/SensorEventQueue.h>
#include <sensor/SensorManager.h>
#include <utils/Looper.h>

#include "QuaternionUtil.h"

namespace android {
namespace media {
namespace {

// Identifier to use for our event queue on the loop.
// The number 19 is arbitrary, only useful if using multiple objects on the same looper.
constexpr int kIdent = 19;

static inline Looper* ALooper_to_Looper(ALooper* alooper) {
    return reinterpret_cast<Looper*>(alooper);
}

static inline ALooper* Looper_to_ALooper(Looper* looper) {
    return reinterpret_cast<ALooper*>(looper);
}

/**
 * RAII-wrapper around SensorEventQueue, which unregisters it on destruction.
 */
class EventQueueGuard {
  public:
    EventQueueGuard(const sp<SensorEventQueue>& queue, Looper* looper) : mQueue(queue) {
        mQueue->looper = Looper_to_ALooper(looper);
        mQueue->requestAdditionalInfo = false;
        looper->addFd(mQueue->getFd(), kIdent, ALOOPER_EVENT_INPUT, nullptr, nullptr);
    }

    ~EventQueueGuard() {
        if (mQueue) {
            ALooper_to_Looper(mQueue->looper)->removeFd(mQueue->getFd());
        }
    }

    EventQueueGuard(const EventQueueGuard&) = delete;
    EventQueueGuard& operator=(const EventQueueGuard&) = delete;

    [[nodiscard]] SensorEventQueue* get() const { return mQueue.get(); }

  private:
    sp<SensorEventQueue> mQueue;
};

/**
 * RAII-wrapper around an enabled sensor, which disables it upon destruction.
 */
class SensorEnableGuard {
  public:
    SensorEnableGuard(const sp<SensorEventQueue>& queue, int32_t sensor)
        : mQueue(queue), mSensor(sensor) {}

    ~SensorEnableGuard() {
        if (mSensor != SensorPoseProvider::INVALID_HANDLE) {
            int ret = mQueue->disableSensor(mSensor);
            if (ret) {
                ALOGE("Failed to disable sensor: %s", strerror(ret));
            }
        }
    }

    SensorEnableGuard(const SensorEnableGuard&) = delete;
    SensorEnableGuard& operator=(const SensorEnableGuard&) = delete;

    // Enable moving.
    SensorEnableGuard(SensorEnableGuard&& other) : mQueue(other.mQueue), mSensor(other.mSensor) {
        other.mSensor = SensorPoseProvider::INVALID_HANDLE;
    }

  private:
    sp<SensorEventQueue> const mQueue;
    int32_t mSensor;
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
        mLooper->wake();
        mThread.join();
    }

    bool startSensor(int32_t sensor, std::chrono::microseconds samplingPeriod) override {
        // Figure out the sensor's data format.
        DataFormat format = getSensorFormat(sensor);
        if (format == DataFormat::kUnknown) {
            ALOGE("Unknown format for sensor %" PRId32, sensor);
            return false;
        }

        {
            std::lock_guard lock(mMutex);
            mEnabledSensorFormats.emplace(sensor, format);
        }

        // Enable the sensor.
        if (mQueue->enableSensor(sensor, samplingPeriod.count(), 0, 0)) {
            ALOGE("Failed to enable sensor");
            std::lock_guard lock(mMutex);
            mEnabledSensorFormats.erase(sensor);
            return false;
        }

        mEnabledSensors.emplace(sensor, SensorEnableGuard(mQueue.get(), sensor));
        return true;
    }

    void stopSensor(int handle) override {
        mEnabledSensors.erase(handle);
        std::lock_guard lock(mMutex);
        mEnabledSensorFormats.erase(handle);
    }

  private:
    enum DataFormat {
        kUnknown,
        kQuaternion,
        kRotationVectorsAndFlags,
    };

    struct PoseEvent {
        Pose3f pose;
        std::optional<Twist3f> twist;
        bool isNewReference;
    };

    sp<Looper> mLooper;
    Listener* const mListener;
    SensorManager* const mSensorManager;
    std::thread mThread;
    std::mutex mMutex;
    std::map<int32_t, SensorEnableGuard> mEnabledSensors;
    std::map<int32_t, DataFormat> mEnabledSensorFormats GUARDED_BY(mMutex);
    sp<SensorEventQueue> mQueue;

    // We must do some of the initialization operations on the worker thread, because the API relies
    // on the thread-local looper. In addition, as a matter of convenience, we store some of the
    // state on the stack.
    // For that reason, we use a two-step initialization approach, where the ctor mostly just starts
    // the worker thread and that thread would notify, via the promise below whenever initialization
    // is finished, and whether it was successful.
    std::promise<bool> mInitPromise;

    SensorPoseProviderImpl(const char* packageName, Listener* listener)
        : mListener(listener),
          mSensorManager(&SensorManager::getInstanceForPackage(String16(packageName))),
          mThread([this] { threadFunc(); }) {}

    void initFinished(bool success) { mInitPromise.set_value(success); }

    bool waitInitFinished() { return mInitPromise.get_future().get(); }

    void threadFunc() {
        // Obtain looper.
        mLooper = Looper::prepare(ALOOPER_PREPARE_ALLOW_NON_CALLBACKS);

        // Create event queue.
        mQueue = mSensorManager->createEventQueue();

        if (mQueue == nullptr) {
            ALOGE("Failed to create a sensor event queue");
            initFinished(false);
            return;
        }

        EventQueueGuard eventQueueGuard(mQueue, mLooper.get());

        initFinished(true);

        while (true) {
            int ret = mLooper->pollOnce(-1 /* no timeout */, nullptr, nullptr, nullptr);

            switch (ret) {
                case ALOOPER_POLL_WAKE:
                    // Normal way to exit.
                    return;

                case kIdent:
                    // Possible events on our queue.
                    break;

                default:
                    ALOGE("Unexpected status out of Looper::pollOnce: %d", ret);
            }

            // Process an event.
            ASensorEvent event;
            ssize_t actual = mQueue->read(&event, 1);
            if (actual > 0) {
                mQueue->sendAck(&event, actual);
            }
            ssize_t size = mQueue->filterEvents(&event, actual);

            if (size < 0 || size > 1) {
                ALOGE("Unexpected return value from SensorEventQueue::filterEvents: %zd", size);
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
        DataFormat format;
        {
            std::lock_guard lock(mMutex);
            auto iter = mEnabledSensorFormats.find(event.sensor);
            if (iter == mEnabledSensorFormats.end()) {
                // This can happen if we have any pending events shortly after stopping.
                return;
            }
            format = iter->second;
        }
        auto value = parseEvent(event, format);
        mListener->onPose(event.timestamp, event.sensor, value.pose, value.twist,
                          value.isNewReference);
    }

    DataFormat getSensorFormat(int32_t handle) {
        std::optional<const Sensor> sensor = getSensorByHandle(handle);
        if (!sensor) {
            ALOGE("Sensor not found: %d", handle);
            return DataFormat::kUnknown;
        }
        if (sensor->getType() == ASENSOR_TYPE_ROTATION_VECTOR ||
            sensor->getType() == ASENSOR_TYPE_GAME_ROTATION_VECTOR) {
            return DataFormat::kQuaternion;
        }

        if (sensor->getStringType() == "com.google.hardware.sensor.hid_dynamic.headtracker") {
            return DataFormat::kRotationVectorsAndFlags;
        }

        return DataFormat::kUnknown;
    }

    std::optional<const Sensor> getSensorByHandle(int32_t handle) {
        const Sensor* const* list;
        ssize_t size;

        // Search static sensor list.
        size = mSensorManager->getSensorList(&list);
        if (size < 0) {
            ALOGE("getSensorList failed with error code %zd", size);
            return std::nullopt;
        }
        for (size_t i = 0; i < size; ++i) {
            if (list[i]->getHandle() == handle) {
                return *list[i];
            }
        }

        // Search dynamic sensor list.
        Vector<Sensor> dynList;
        size = mSensorManager->getDynamicSensorList(dynList);
        if (size < 0) {
            ALOGE("getDynamicSensorList failed with error code %zd", size);
            return std::nullopt;
        }
        for (size_t i = 0; i < size; ++i) {
            if (dynList[i].getHandle() == handle) {
                return dynList[i];
            }
        }

        return std::nullopt;
    }

    static PoseEvent parseEvent(const ASensorEvent& event, DataFormat format) {
        // TODO(ytai): Add more types.
        switch (format) {
            case DataFormat::kQuaternion: {
                Eigen::Quaternionf quat(event.data[3], event.data[0], event.data[1], event.data[2]);
                // Adapt to different frame convention.
                quat *= rotateX(-M_PI_2);
                return PoseEvent{Pose3f(quat), std::optional<Twist3f>(), false};
            }

            case DataFormat::kRotationVectorsAndFlags: {
                // Custom sensor, assumed to contain:
                // 3 floats representing orientation as a rotation vector (in rad).
                // 3 floats representing angular velocity as a rotation vector (in rad/s).
                // 1 uint32_t of flags, where:
                // - LSb is '1' iff the given sample is the first one in a new frame of reference.
                // - The rest of the bits are reserved for future use.
                Eigen::Vector3f rotation = {event.data[0], event.data[1], event.data[2]};
                Eigen::Vector3f twist = {event.data[3], event.data[4], event.data[5]};
                Eigen::Quaternionf quat = rotationVectorToQuaternion(rotation);
                uint32_t flags = *reinterpret_cast<const uint32_t*>(&event.data[6]);
                return PoseEvent{Pose3f(quat), Twist3f(Eigen::Vector3f::Zero(), twist),
                                 (flags & (1 << 0)) != 0};
            }

            default:
                LOG_ALWAYS_FATAL("Unexpected sensor type: %d", static_cast<int>(format));
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
