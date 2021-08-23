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

#include <media/SensorPoseProvider.h>

using android::media::Pose3f;
using android::media::SensorPoseProvider;
using android::media::Twist3f;

const char kPackageName[] = "SensorPoseProvider-example";

class Listener : public SensorPoseProvider::Listener {
  public:
    void onPose(int64_t timestamp, int32_t handle, const Pose3f& pose,
                const std::optional<Twist3f>& twist) override {
        std::cout << "onPose t=" << timestamp << " sensor=" << handle << " pose=" << pose
                  << " twist=";
        if (twist.has_value()) {
            std::cout << twist.value();
        } else {
            std::cout << "<none>";
        }
        std::cout << std::endl;
    }
};

int main() {
    ASensorManager* sensor_manager = ASensorManager_getInstanceForPackage(kPackageName);
    if (!sensor_manager) {
        std::cerr << "Failed to get a sensor manager" << std::endl;
        return 1;
    }

    const ASensor* headSensor =
            ASensorManager_getDefaultSensor(sensor_manager, SENSOR_TYPE_GAME_ROTATION_VECTOR);
    const ASensor* screenSensor =
            ASensorManager_getDefaultSensor(sensor_manager, SENSOR_TYPE_ROTATION_VECTOR);

    Listener listener;

    std::unique_ptr<SensorPoseProvider> provider =
            SensorPoseProvider::create(kPackageName, &listener);
    int32_t headHandle = provider->startSensor(headSensor, std::chrono::milliseconds(500));
    sleep(2);
    provider->startSensor(screenSensor, std::chrono::milliseconds(500));
    sleep(2);
    provider->stopSensor(headHandle);
    sleep(2);
    return 0;
}
