/*
 * Copyright 2020 The Android Open Source Project
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

#include <functional>
#include <string>
#include <vector>

#include <utils/String8.h>

#include "fuzzer/FuzzedDataProvider.h"
#include "mediautils/BatteryNotifier.h"

static constexpr int kMaxOperations = 30;
static constexpr int kMaxStringLength = 500;
using android::BatteryNotifier;

std::vector<std::function<void(std::string /*flashlight_name*/, std::string /*camera_name*/,
                               uid_t /*video_id*/, uid_t /*audio_id*/, uid_t /*light_id*/,
                               uid_t /*camera_id*/)>>
    operations = {
        [](std::string, std::string, uid_t, uid_t, uid_t, uid_t) -> void {
            BatteryNotifier::getInstance().noteResetVideo();
        },
        [](std::string, std::string, uid_t, uid_t, uid_t, uid_t) -> void {
            BatteryNotifier::getInstance().noteResetAudio();
        },
        [](std::string, std::string, uid_t, uid_t, uid_t, uid_t) -> void {
            BatteryNotifier::getInstance().noteResetFlashlight();
        },
        [](std::string, std::string, uid_t, uid_t, uid_t, uid_t) -> void {
            BatteryNotifier::getInstance().noteResetCamera();
        },
        [](std::string, std::string, uid_t video_id, uid_t, uid_t, uid_t) -> void {
            BatteryNotifier::getInstance().noteStartVideo(video_id);
        },
        [](std::string, std::string, uid_t video_id, uid_t, uid_t, uid_t) -> void {
            BatteryNotifier::getInstance().noteStopVideo(video_id);
        },
        [](std::string, std::string, uid_t, uid_t audio_id, uid_t, uid_t) -> void {
            BatteryNotifier::getInstance().noteStartAudio(audio_id);
        },
        [](std::string, std::string, uid_t, uid_t audio_id, uid_t, uid_t) -> void {
            BatteryNotifier::getInstance().noteStopAudio(audio_id);
        },
        [](std::string flashlight_name, std::string, uid_t, uid_t, uid_t light_id, uid_t) -> void {
            android::String8 name(flashlight_name.c_str());
            BatteryNotifier::getInstance().noteFlashlightOn(name, light_id);
        },
        [](std::string flashlight_name, std::string, uid_t, uid_t, uid_t light_id, uid_t) -> void {
            android::String8 name(flashlight_name.c_str());
            BatteryNotifier::getInstance().noteFlashlightOff(name, light_id);
        },
        [](std::string, std::string camera_name, uid_t, uid_t, uid_t, uid_t camera_id) -> void {
            android::String8 name(camera_name.c_str());
            BatteryNotifier::getInstance().noteStartCamera(name, camera_id);
        },
        [](std::string, std::string camera_name, uid_t, uid_t, uid_t, uid_t camera_id) -> void {
            android::String8 name(camera_name.c_str());
            BatteryNotifier::getInstance().noteStopCamera(name, camera_id);
        },
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzedDataProvider data_provider(data, size);
    std::string camera_name = data_provider.ConsumeRandomLengthString(kMaxStringLength);
    std::string flashlight_name = data_provider.ConsumeRandomLengthString(kMaxStringLength);
    uid_t video_id = data_provider.ConsumeIntegral<uid_t>();
    uid_t audio_id = data_provider.ConsumeIntegral<uid_t>();
    uid_t light_id = data_provider.ConsumeIntegral<uid_t>();
    uid_t camera_id = data_provider.ConsumeIntegral<uid_t>();
    size_t ops_run = 0;
    while (data_provider.remaining_bytes() > 0 && ops_run++ < kMaxOperations) {
        uint8_t op = data_provider.ConsumeIntegralInRange<uint8_t>(0, operations.size() - 1);
        operations[op](flashlight_name, camera_name, video_id, audio_id, light_id, camera_id);
    }
    return 0;
}
