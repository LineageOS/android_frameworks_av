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

#include <unistd.h>
#include <iostream>

#include <android/sensor.h>
#include <hardware/sensors.h>
#include <utils/SystemClock.h>

#include <media/SensorPoseProvider.h>
#include <sensor/Sensor.h>
#include <sensor/SensorManager.h>

using android::elapsedRealtimeNano;
using android::Sensor;
using android::SensorManager;
using android::String16;
using android::media::Pose3f;
using android::media::SensorPoseProvider;
using android::media::Twist3f;

using namespace std::chrono_literals;

const char kPackageName[] = "SensorPoseProvider-example";

class Listener : public SensorPoseProvider::Listener {
  public:
    void onPose(int64_t timestamp, int32_t handle, const Pose3f& pose,
                const std::optional<Twist3f>& twist, bool isNewReference) override {
        int64_t now = elapsedRealtimeNano();

        std::cout << "onPose t=" << timestamp
                  << " lag=" << ((now - timestamp) / 1e6) << "[ms]"
                  << " sensor=" << handle
                  << " pose=" << pose
                  << " twist=";
        if (twist.has_value()) {
            std::cout << twist.value();
        } else {
            std::cout << "<none>";
        }
        std::cout << " isNewReference=" << isNewReference << std::endl;
    }
};

int main() {
    SensorManager& sensorManager = SensorManager::getInstanceForPackage(String16(kPackageName));

    const Sensor* headSensor = sensorManager.getDefaultSensor(SENSOR_TYPE_GAME_ROTATION_VECTOR);
    const Sensor* screenSensor = sensorManager.getDefaultSensor(SENSOR_TYPE_ROTATION_VECTOR);

    Listener listener;

    std::unique_ptr<SensorPoseProvider> provider =
            SensorPoseProvider::create(kPackageName, &listener);
    if (!provider->startSensor(headSensor->getHandle(), 500ms)) {
        std::cout << "Failed to start head sensor" << std::endl;
    }
    sleep(2);
    if (!provider->startSensor(screenSensor->getHandle(), 500ms)) {
        std::cout << "Failed to start screenSensor sensor" << std::endl;
    }
    sleep(2);
    provider->stopSensor(headSensor->getHandle());
    sleep(2);
    return 0;
}
