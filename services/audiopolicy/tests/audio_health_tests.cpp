/*
 * Copyright (C) 2019 The Android Open Source Project
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

#define LOG_TAG "AudioPolicy_Boot_Test"

#include <string>
#include <unordered_set>

#include <gtest/gtest.h>

#include <media/AudioSystem.h>
#include <media/TypeConverter.h>
#include <system/audio.h>
#include <utils/Log.h>

#include "AudioPolicyManagerTestClient.h"
#include "AudioPolicyTestManager.h"

using namespace android;

TEST(AudioHealthTest, AttachedDeviceFound) {
    unsigned int numPorts;
    unsigned int generation1;
    unsigned int generation;
    struct audio_port_v7 *audioPorts = nullptr;
    int attempts = 10;
    do {
        if (attempts-- < 0) {
            free(audioPorts);
            GTEST_FAIL() << "Query audio ports time out";
        }
        numPorts = 0;
        ASSERT_EQ(NO_ERROR, AudioSystem::listAudioPorts(
                AUDIO_PORT_ROLE_NONE, AUDIO_PORT_TYPE_DEVICE, &numPorts, nullptr, &generation1));
        if (numPorts == 0) {
            free(audioPorts);
            GTEST_FAIL() << "Number of audio ports should not be zero";
        }

        audioPorts = (struct audio_port_v7 *)realloc(
                audioPorts, numPorts * sizeof(struct audio_port_v7));
        status_t status = AudioSystem::listAudioPorts(
                AUDIO_PORT_ROLE_NONE, AUDIO_PORT_TYPE_DEVICE, &numPorts, audioPorts, &generation);
        if (status != NO_ERROR) {
            free(audioPorts);
            GTEST_FAIL() << "Query audio ports failed";
        }
    } while (generation1 != generation);
    std::unordered_set<audio_devices_t> attachedDevices;
    for (int i = 0 ; i < numPorts; i++) {
        attachedDevices.insert(audioPorts[i].ext.device.type);
    }
    free(audioPorts);

    AudioPolicyManagerTestClient client;
    AudioPolicyTestManager manager(&client);
    manager.loadConfig();
    ASSERT_NE("AudioPolicyConfig::setDefault", manager.getConfig().getSource());

    for (auto desc : manager.getConfig().getInputDevices()) {
        if (attachedDevices.find(desc->type()) == attachedDevices.end()) {
            std::string deviceType;
            (void)DeviceConverter::toString(desc->type(), deviceType);
            ADD_FAILURE() << "Input device \"" << deviceType << "\" not found";
        }
    }
    for (auto desc : manager.getConfig().getOutputDevices()) {
        if (attachedDevices.find(desc->type()) == attachedDevices.end()) {
            std::string deviceType;
            (void)DeviceConverter::toString(desc->type(), deviceType);
            ADD_FAILURE() << "Output device \"" << deviceType << "\" not found";
        }
    }
}

TEST(AudioHealthTest, ConnectSupportedDevice) {
    AudioPolicyManagerTestClient client;
    AudioPolicyTestManager manager(&client);
    manager.loadConfig();
    ASSERT_NE("AudioPolicyConfig::setDefault", manager.getConfig().getSource());

    DeviceVector devices;
    for (const auto& hwModule : manager.getConfig().getHwModules()) {
        for (const auto& profile : hwModule->getOutputProfiles()) {
            devices.merge(profile->getSupportedDevices());
        }
        for (const auto& profile : hwModule->getInputProfiles()) {
            devices.merge(profile->getSupportedDevices());
        }
    }
    for (const auto& device : devices) {
        if (!audio_is_bluetooth_out_sco_device(device->type()) &&
            !audio_is_bluetooth_in_sco_device(device->type())) {
            // There are two reasons to only test connecting BT devices.
            // 1) It is easier to construct a fake address.
            // 2) This test will be run in presubmit. In that case, it makes sense to make the test
            //    processing time short.
            continue;
        }
        std::string address = "11:22:33:44:55:66";
        ASSERT_EQ(AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE,
                AudioSystem::getDeviceConnectionState(device->type(), address.c_str()));
        ASSERT_EQ(NO_ERROR, AudioSystem::setDeviceConnectionState(
                device->type(), AUDIO_POLICY_DEVICE_STATE_AVAILABLE, address.c_str(),
                "" /*device_name*/, AUDIO_FORMAT_DEFAULT));
        ASSERT_EQ(AUDIO_POLICY_DEVICE_STATE_AVAILABLE,
                AudioSystem::getDeviceConnectionState(device->type(), address.c_str()));
        ASSERT_EQ(NO_ERROR, AudioSystem::setDeviceConnectionState(
                device->type(), AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE, address.c_str(),
                "" /*device_name*/, AUDIO_FORMAT_DEFAULT));
        ASSERT_EQ(AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE,
                AudioSystem::getDeviceConnectionState(device->type(), address.c_str()));
    }
}
